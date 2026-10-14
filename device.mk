#
# Copyright (C) 2019 The LineageOS Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

DEVICE_PACKAGE_OVERLAYS += $(LOCAL_PATH)/overlay

# Audio
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/configs/audio/mixer_gains.xml:$(TARGET_COPY_OUT_VENDOR)/etc/mixer_gains.xml

# Inherit from common
$(call inherit-product, device/samsung/universal8895-common/device-common.mk)

$(call inherit-product-if-exists, vendor/samsung/dream2lte/dream2lte-vendor.mk)

# Headless server (dead screen): ADB must be on from first boot.
# ADB authorization is disabled (WITH_ADB_INSECURE=true in build.sh -> ro.adb.secure=0).
# PRODUCT_ADB_KEYS below is only a fallback if a build is made without it.
PRODUCT_SYSTEM_PROPERTIES += \
    persist.sys.usb.config=mtp,adb

# Pre-authorized ADB key(s) for the headless setup (installed as /adb_keys on userdebug/eng).
PRODUCT_ADB_KEYS := device/samsung/dream2lte/configs/adb/adb_keys.pub

# headless_su: password-gated root (Termux) without Magisk; replaces AOSP debug su.
# headless_boot runs the root boot scripts in /data/local/boot.d.
PRODUCT_PACKAGES += \
    headless_su \
    set_root_pwd \
    headless_boot

# ROM boot scripts run by headless_boot before /data/local/boot.d: Termux SSH
# (sshd on 8022) and USB snapshots after each boot (/data/local/usb-boot.log).
PRODUCT_PACKAGES += \
    headless_boot_20-termux \
    headless_boot_30-usb-report \
    headless_termux_sshd

# SSH public keys for Termux's sshd: not in git, copied in by the Mac build
# script before every build (the build host's key); installed only if present.
PRODUCT_COPY_FILES += \
    $(foreach f,$(wildcard device/samsung/dream2lte/headless_apps/termux_authorized_keys),\
        $(f):$(TARGET_COPY_OUT_SYSTEM)/etc/headless/termux_authorized_keys)
