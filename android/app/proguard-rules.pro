# JNI reflective access
-keepclasseswithmembernames class * {
    native <methods>;
}

-keep class com.neuronencrypt.app.NeuronEncryptNative {
    native <methods>;
}

-keep interface com.neuronencrypt.app.ProgressListener {
    *;
}

# The native side calls this interface *by name* through JNI
# (`env.call_method(..., "onScrubReport", ...)`), so R8 must not rename or
# remove it. Without this rule the scrub report silently never reached the UI
# in release (minified) builds — the native call result is discarded, so the
# failure was invisible.
-keep interface com.neuronencrypt.app.ScrubReportListener {
    *;
}

-keep class com.neuronencrypt.app.NeuronEncryptException {
    *;
}
