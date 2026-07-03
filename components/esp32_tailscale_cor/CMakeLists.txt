idf_component_register(
    SRCS
        "blake2s.cpp"
        "noise_ik.cpp"
        "ts_ctrl.cpp"
        "ts_h2.cpp"
        "x25519.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_timer
        lwip
        mbedtls
        nvs_flash
)
