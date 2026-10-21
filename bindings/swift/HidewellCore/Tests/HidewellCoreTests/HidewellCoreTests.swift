import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import HidewellCore

/// Software oracle for tests ONLY (never ship): HMAC chain + AES-GCM sealing.
final class SoftwareOracle: HardwareOracle, @unchecked Sendable {
    private let key = SymmetricKey(data: Data(repeating: 7, count: 32))
    private static let epoch = withUnsafeBytes(of: UUID().uuid) { Data($0) }

    func securityLevel() -> SecurityLevel { .softwareMock }

    func clockSample() throws -> ClockSample {
        let nanos = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
        guard nanos != 0 else { throw HidewellError.OracleFailed }
        return ClockSample(epoch: Self.epoch, elapsedMillis: nanos / 1_000_000)
    }

    func chainStep(input: Data) throws -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: input, using: key))
    }

    func sealDeviceSecret(secret: Data) throws -> Data {
        try AES.GCM.seal(secret, using: key).combined!
    }

    func openDeviceSecret(sealed: Data) throws -> Data {
        do {
            return try AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: key)
        } catch {
            throw HidewellError.OracleSealedBlobInvalid
        }
    }
}

final class HidewellCoreTests: XCTestCase {
    // Small container; release-minimum KDF (64 MiB Argon2id, 4 chain steps).
    let geometry = Geometry(
        chunkSize: 65_536, blockSize: 4096, segmentBlocks: 4,
        buckets: [64 * 65_536, 128 * 65_536], coverChunksPerCommit: 2,
        fillerPermilleMin: 50, fillerPermilleMax: 150, fillerSlotsMin: 1, fillerSlotsMax: 8)
    let params = KdfParams(chainSteps: 4, argonMKib: 65_536, argonT: 1, argonP: 1)
    let pattern: [Data] = [Data([7, 0, 11, 22, 13, 4, 8, 15, 21])]

    func testCreateUnlockImportRead() throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("hidewell-\(UUID().uuidString).bin").path
        defer { try? FileManager.default.removeItem(atPath: path) }
        let oracle = SoftwareOracle()
        let words = generatePhrase()
        XCTAssertEqual(words.count, 12)
        XCTAssertTrue(validatePhrase(words: words))
        XCTAssertEqual(p256HashToCurve(input: Data([1, 2, 3])).count, 65)

        let created = try createDevice(
            path: path, oracleImpl: oracle, geometry: geometry, params: params,
            phraseWords: words, firstPattern: pattern)
        XCTAssertEqual(created.initialEntries.count, 16)
        let meta = NewItem(name: "IMG_0001.HEIC", mime: "image/heic", created: 1, modified: 2, albums: [], tags: [])
        let body = Data((0..<50_000).map { UInt8(truncatingIfNeeded: $0 &* 31) })
        let id = try created.vault.import(meta: meta, data: body, thumbnail: Data([9, 9]))

        // Streaming import from chunks.
        let w = try created.vault.beginImport(meta: meta, size: UInt64(body.count))
        var off = 0
        while off < body.count {
            let end = min(off + 7000, body.count)
            try w.write(data: body.subdata(in: off..<end))
            off = end
        }
        let id2 = try w.finish(thumbnail: nil)
        created.vault.lock()

        // Reopen from the file with the stored sealed secret.
        let device = try Device.open(
            path: path, oracleImpl: oracle, geometry: geometry,
            sealedDeviceSecret: created.sealedDeviceSecret)
        XCTAssertThrowsError(try device.unlock(strokes: [Data([0, 6, 12, 18, 24, 23, 17])])) {
            XCTAssertEqual($0 as? HidewellError, .WrongPattern)
        }
        let vault = try device.unlock(strokes: pattern)
        XCTAssertEqual(try vault.itemCount(), 2)
        XCTAssertEqual(try vault.read(id: id, offset: 0, length: UInt64(body.count)), body)
        XCTAssertEqual(try vault.read(id: id2, offset: 12_345, length: 100), body.subdata(in: 12_345..<12_445))
        XCTAssertEqual(try vault.thumbnail(id: id), Data([9, 9]))
        XCTAssertEqual(try device.securityLevel(), .softwareMock)

        // Unsized streaming import + opaque extra; counters.
        let live = NewItem(name: "IMG_0001.MOV", mime: "video/quicktime", created: 1, modified: 2,
                           albums: [], tags: [], extra: Data("pair:1".utf8))
        let uw = try vault.beginImportUnsized(meta: live)
        try uw.write(data: body.subdata(in: 0..<30_000))
        try uw.write(data: body.subdata(in: 30_000..<body.count))
        let id3 = try uw.finish(thumbnail: nil)
        XCTAssertEqual(try vault.item(id: id3).size, UInt64(body.count))
        XCTAssertEqual(try vault.item(id: id3).extra, Data("pair:1".utf8))
        try vault.setItemExtra(id: id, extra: Data([1]))
        XCTAssertEqual(try vault.item(id: id).extra, Data([1]))
        XCTAssertEqual(try vault.read(id: id3, offset: 100, length: 50), body.subdata(in: 100..<150))
        XCTAssertEqual(try vault.wipeAfter(), 0)
        // One wrong attempt earlier; a later success does not erase it.
        XCTAssertEqual(try device.failedAttempts(), 1)
        XCTAssertEqual(try device.retryAfterSeconds(), 0)
        // A sub-policy stroke is rejected without counting.
        XCTAssertThrowsError(try device.unlock(strokes: [Data([0, 1, 2])])) {
            XCTAssertEqual($0 as? HidewellError, .InvalidPattern)
        }
        XCTAssertEqual(try device.failedAttempts(), 1)

        // Forgotten pattern, recovered with the phrase alone (no cloud).
        let found = try device.recoverWithPhrase(phraseWords: words)
        XCTAssertEqual(found.count, 1)
        XCTAssertTrue(found[0].presentLocally)
        XCTAssertFalse(found[0].isDuress)
        let newPattern: [Data] = [Data([12, 1, 10, 23, 14, 3, 6, 19])]
        try device.resetPatternWithPhrase(phraseWords: words, index: found[0].index, strokes: newPattern)
        // The reset invalidates handles opened before it.
        let reopened = try device.unlock(strokes: newPattern)
        XCTAssertEqual(try reopened.itemCount(), 3)
        XCTAssertTrue(try reopened.backupEnabled())

        // Phrase check, blocked shape names, thumbnail backfill.
        XCTAssertTrue(try device.verifyPhrase(phraseWords: words))
        XCTAssertFalse(try device.verifyPhrase(phraseWords: generatePhrase()))
        XCTAssertEqual(try patternStrength(strokes: [Data([0, 4, 20, 24])]).blockedShape, .zShape)
        try reopened.setThumbnail(id: id2, bytes: Data([7, 7, 7]))
        XCTAssertEqual(try reopened.thumbnail(id: id2), Data([7, 7, 7]))
        // In-place content replacement.
        try reopened.replaceContent(id: id2, bytes: Data("edited".utf8), modified: 42)
        XCTAssertEqual(try reopened.read(id: id2, offset: 0, length: 100), Data("edited".utf8))
        XCTAssertEqual(try reopened.item(id: id2).size, 6)
        XCTAssertEqual(try reopened.item(id: id2).modified, 42)
        XCTAssertEqual(try reopened.thumbnail(id: id2), Data([7, 7, 7]))
        XCTAssertThrowsError(try reopened.replaceContent(id: 999, bytes: Data([1]), modified: 0)) {
            XCTAssertEqual($0 as? HidewellError, .NotFound)
        }

        // Protection info.
        let info = try device.protectionInfo()
        XCTAssertEqual(info.securityLevel, .softwareMock)
        XCTAssertGreaterThan(info.chainSteps, 0)
        XCTAssertNil(info.estimatedAttemptMillis)

        // Vault names.
        try reopened.setName(name: "  Main  ")
        XCTAssertEqual(try reopened.name(), "Main")
        XCTAssertThrowsError(try reopened.setName(name: String(repeating: "é", count: 65))) {
            XCTAssertEqual($0 as? HidewellError, .InvalidArgument)
        }
        XCTAssertEqual(try reopened.decoys(), [])

        // Erase.
        try device.erase()
        XCTAssertThrowsError(try device.unlock(strokes: newPattern)) {
            XCTAssertEqual($0 as? HidewellError, .Locked)
        }
    }
}
