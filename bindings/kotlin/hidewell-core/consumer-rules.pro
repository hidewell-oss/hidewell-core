# JNA and the generated UniFFI bindings use reflection.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class com.sentrybrain.hidewell.core.** { *; }
