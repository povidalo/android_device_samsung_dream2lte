#
# Copyright (C) 2019 The LineageOS Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# inherit from common
-include device/samsung/universal8895-common/BoardConfigCommon.mk

DEVICE_PATH := device/samsung/dream2lte

# Assert
TARGET_OTA_ASSERT_DEVICE := dream2lte

# Kernel. The fragment (USB hardware, Docker, network filesystems) is merged on
# top of the defconfig. Fragments are looked up relative to the kernel's
# arch/arm64/configs/, hence the path back up to this device tree. It detours
# through ../../../arch/arm64/configs on purpose: the kernel make runs in
# obj/KERNEL_OBJ, which is as deep as arch/arm64/configs, so a plain
# ../../../../../../device/... also names the real file from there and make
# then calls the target "up to date" instead of merging it.
TARGET_KERNEL_CONFIG := \
    exynos8895-dream2lte_defconfig \
    ../../../arch/arm64/configs/../../../../../../device/samsung/dream2lte/configs/kernel/headless_server.config
# Lineage recovery (built, but never flashed: the zip writes only system and
# boot, TWRP stays) keeps the stock kernel. With the server kernel it exceeded
# the 46 MB recovery partition and failed the build.
TARGET_KERNEL_RECOVERY_CONFIG := exynos8895-dream2lte_defconfig

# inherit from the proprietary version
-include vendor/samsung/dream2lte/BoardConfigVendor.mk

# headless_su (password-gated root daemon + su)
SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += device/samsung/dream2lte/headless_su/sepolicy
