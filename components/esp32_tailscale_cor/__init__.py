# SPDX-FileCopyrightText: 2025 CorCorMS (https://github.com/CorCorMS)
# SPDX-License-Identifier: Apache-2.0
#
# See LICENSE for full license text.
# Third-party code in this directory may have separate licensing.
#
import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import binary_sensor, sensor, text_sensor, esp32
from esphome.const import CONF_ID, ENTITY_CATEGORY_DIAGNOSTIC
import os

CODEOWNERS = ["@CorCorMS"]
DEPENDENCIES = ["network"]
AUTO_LOAD = ["binary_sensor", "sensor", "text_sensor"]

esp32_tailscale_cor_ns = cg.esphome_ns.namespace("esp32_tailscale_cor")
ESP32TailscaleCORComponent = esp32_tailscale_cor_ns.class_("ESP32TailscaleCORComponent", cg.PollingComponent)

CONF_AUTH_KEY = "auth_key"
CONF_DEVICE_NAME = "device_name"
CONF_CONNECTED = "connected"
CONF_STATE = "state"
CONF_VPN_IP = "vpn_ip"
CONF_PEER_COUNT = "peer_count"
CONF_IDENTITY_STATUS = "identity_status"
CONF_MACHINE_KEY_ID = "machine_key_id"
CONF_NODE_KEY_ID = "node_key_id"
CONF_WIRE_INGRESS = "wire_ingress"
CONF_INGRESS_ENABLED = "ingress_enabled"
CONF_ADVERTISED_SERVICE_PORT = "advertised_service_port"

COMP_DIR = os.path.dirname(os.path.realpath(__file__))

CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(ESP32TailscaleCORComponent),
            cv.Required(CONF_AUTH_KEY): cv.All(
                cv.sensitive(cv.string_strict), cv.Length(min=1)
            ),
            cv.Optional(CONF_DEVICE_NAME): cv.string_strict,
            cv.Optional(CONF_WIRE_INGRESS, default=False): cv.boolean,
            cv.Optional(CONF_INGRESS_ENABLED, default=False): cv.boolean,
            cv.Optional(CONF_ADVERTISED_SERVICE_PORT, default=0): cv.port,
            cv.Optional(CONF_CONNECTED): binary_sensor.binary_sensor_schema(
                icon="mdi:lan-connect", entity_category=ENTITY_CATEGORY_DIAGNOSTIC
            ),
            cv.Optional(CONF_STATE): text_sensor.text_sensor_schema(
                icon="mdi:state-machine", entity_category=ENTITY_CATEGORY_DIAGNOSTIC
            ),
            cv.Optional(CONF_VPN_IP): text_sensor.text_sensor_schema(
                icon="mdi:ip-network", entity_category=ENTITY_CATEGORY_DIAGNOSTIC
            ),
            cv.Optional(CONF_PEER_COUNT): sensor.sensor_schema(
                accuracy_decimals=0,
                icon="mdi:account-network",
                entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            ),
            cv.Optional(CONF_IDENTITY_STATUS): text_sensor.text_sensor_schema(
                icon="mdi:key-chain",
                entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            ),
            cv.Optional(CONF_MACHINE_KEY_ID): text_sensor.text_sensor_schema(
                icon="mdi:fingerprint",
                entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            ),
            cv.Optional(CONF_NODE_KEY_ID): text_sensor.text_sensor_schema(
                icon="mdi:key-variant",
                entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            ),
        }
    ).extend(cv.polling_component_schema("5s")),
    cv.only_on_esp32,
)

async def to_code(config):
    comp_dir = os.path.dirname(os.path.realpath(__file__))
    src_dirs = [comp_dir]
    for d in src_dirs:
        cg.add_build_flag(f"-I{d}")
    cg.add_define("USE_ESP32_TAILSCALE_COR")
    esp32.add_idf_sdkconfig_option("CONFIG_MBEDTLS_CHACHAPOLY_C", True)
    esp32.add_idf_sdkconfig_option("CONFIG_MBEDTLS_CHACHA20_C", True)
    esp32.add_idf_sdkconfig_option("CONFIG_MBEDTLS_POLY1305_C", True)
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    cg.add(var.set_auth_key(config[CONF_AUTH_KEY]))
    if CONF_DEVICE_NAME in config:
        cg.add(var.set_device_name(config[CONF_DEVICE_NAME]))
    cg.add(var.set_wire_ingress(config[CONF_WIRE_INGRESS]))
    cg.add(var.set_ingress_enabled(config[CONF_INGRESS_ENABLED]))
    cg.add(var.set_advertised_service_port(config[CONF_ADVERTISED_SERVICE_PORT]))
    if CONF_CONNECTED in config:
        sens = await binary_sensor.new_binary_sensor(config[CONF_CONNECTED])
        cg.add(var.set_connected_sensor(sens))
    if CONF_STATE in config:
        sens = await text_sensor.new_text_sensor(config[CONF_STATE])
        cg.add(var.set_state_sensor(sens))
    if CONF_VPN_IP in config:
        sens = await text_sensor.new_text_sensor(config[CONF_VPN_IP])
        cg.add(var.set_vpn_ip_sensor(sens))
    if CONF_PEER_COUNT in config:
        sens = await sensor.new_sensor(config[CONF_PEER_COUNT])
        cg.add(var.set_peer_count_sensor(sens))
    if CONF_IDENTITY_STATUS in config:
        sens = await text_sensor.new_text_sensor(config[CONF_IDENTITY_STATUS])
        cg.add(var.set_identity_status_sensor(sens))
    if CONF_MACHINE_KEY_ID in config:
        sens = await text_sensor.new_text_sensor(config[CONF_MACHINE_KEY_ID])
        cg.add(var.set_machine_key_id_sensor(sens))
    if CONF_NODE_KEY_ID in config:
        sens = await text_sensor.new_text_sensor(config[CONF_NODE_KEY_ID])
        cg.add(var.set_node_key_id_sensor(sens))
