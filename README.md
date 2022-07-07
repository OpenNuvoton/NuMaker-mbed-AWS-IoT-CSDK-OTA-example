# Example for Firmware OTA with AWS IoT on Nuvoton's Mbed Enabled boards

This is an example to show firmware Over-The-Air (OTA) with [AWS IoT service](https://aws.amazon.com/console/) on Nuvoton's Mbed Enabled boards.
It relies on the following modules:

-   [Mbed OS](https://github.com/ARMmbed/mbed-os):
    Is an open source embedded operating system designed specifically for the "things" in the Internet of Things.
-   [AWS IoT SDK port for Mbed OS](https://github.com/OpenNuvoton/mbed-client-for-aws/):
    Provides the port of the AWS IoT SDK for Mbed OS. It can be used to connect devices running Mbed OS to the AWS IoT Core service over MQTT.

## Support targets

Platform                                                                    |  Connectivity     | Bootloader        | Firmware candidate storage
----------------------------------------------------------------------------|-------------------|-------------------|--------------------------------
NuMaker-IoT-M467                                                            | Wi-Fi ESP8266     | MCUboot           | Internal flash
[NuMaker-PFM-M487](https://developer.mbed.org/platforms/NUMAKER-PFM-M487/)  | Ethernet          | Proprietary       | SPI flash                                 
[NuMaker-IoT-M487](https://os.mbed.com/platforms/NUMAKER-IOT-M487/)         | Wi-Fi ESP8266     | Proprietary       | SPI flash                                 
[NuMaker-M2354](https://os.mbed.com/platforms/NUMAKER-M2354/)               | Wi-Fi ESP8266     | TF-M MCUboot      | SD card                                   

## Support development tools

-   [Arm's Mbed Online Compiler](https://os.mbed.com/docs/mbed-os/v6.6/tools/developing-mbed-online-compiler.html)

    **NOTE**: Support no NuMaker-IoT-M467/NuMaker-PFM-M487/NuMaker-IOT-M487/NuMaker-M2354

-   [Arm's Mbed Studio](https://os.mbed.com/docs/mbed-os/v6.15/build-tools/mbed-studio.html)

-   [Arm's Mbed CLI 2](https://os.mbed.com/docs/mbed-os/v6.15/build-tools/mbed-cli-2.html)

    **NOTE**: Support no NuMaker-IoT-M467/NuMaker-PFM-M487/NuMaker-IOT-M487. See [the issue thread](https://github.com/ARMmbed/mbed-tools/issues/156).

-   [Arm's Mbed CLI 1](https://os.mbed.com/docs/mbed-os/v6.15/tools/developing-mbed-cli.html)

## Developer guide

This section is intended for developers to get started, import the example application, compile with Mbed CLI 1, and get it running firmware OTA with AWS IoT service.

### Hardware requirements

-   NuMaker-IoT-M467 board
-   [NuMaker-IoT-M487 board](https://os.mbed.com/platforms/NUMAKER-IOT-M487/)
-   [NuMaker-M2354 board](https://os.mbed.com/platforms/NUMAKER-M2354/)

**NOTE**: Choose either one as example board for demonstrating below

### Software requirements

-   [Arm's Mbed CLI 1](https://os.mbed.com/docs/mbed-os/v6.15/tools/developing-mbed-cli.html)

-   [Image tool](https://github.com/mcu-tools/mcuboot/blob/main/docs/imgtool.md) (NuMaker-IoT-M467 only)

    **NOTE**: Used for signing application binary for MCUboot

-   [SRecord](http://srecord.sourceforge.net/) (NuMaker-IoT-M467 only)

    **NOTE**: Used for concatenating bootloader binary and application binary

-   [NuMicro ICP Programming Tool](https://www.nuvoton.com/tool-and-software/software-development-tool/programmer/) (NuMaker-IoT-M487 only)

    **NOTE**: Used for flashing onto board

### Hardware setup

-   Firmware candidate storage
    -   NuMaker-IoT-M467: Internal flash
    -   NuMaker-IoT-M487: On-board SPI flash
    -   NuMaker-M2354: Micro SD card plugged-in
-   Switch target board
    -   NuMaker-IoT-M467's Nu-Link2: TX/RX/VCOM to ON, MSG to non-ON
    -   NuMaker-IoT-M487's Nu-Link: TX/RX/VCOM to ON, MSG to ON
    -   NuMaker-M2354's Nu-Link2: TX/RX/VCOM to ON, MSG to non-ON
-   Connect target board to host through USB
    -   NuMaker-IoT-M467: Mbed USB drive shows up in File Browser
    -   NuMaker-IoT-M487: Mbed USB drive shows up in File Browser
    -   NuMaker-M2354: Mbed USB drive shows up in File Browser

### Compile with Mbed CLI 1

In the following, we take NuMaker-IoT-M467, NuMaker-IoT-M487, or NuMaker-M2354 as example board to show this example.

1.  Clone the example and navigate into it
    ```
    $ git clone https://github.com/OpenNuvoton/NuMaker-mbed-AWSn-IoT-CSDK-OTA-example
    $ cd NuMaker-mbed-AWS-IoT-CSDK-OTA-example
    ```
1.  Deploy necessary libraries
    ```
    $ mbed deploy
    ```
1.  Configure network interface
    In `mbed_app.json`, configure WiFi **SSID**/**PASSWORD** (WiFi only).
    ```json
        "nsapi.default-wifi-ssid"                   : "\"SSID\"",
        "nsapi.default-wifi-password"               : "\"PASSWORD\"",
    ```

1.  In `configs/aws_config.h`, provide AWS connection parameters: **AWS_IOT_ENDPOINT**, **CLIENT_IDENTIFIER**, and **THING_NAME**.

1.  In `configs/aws_credentials.c`, provide relevant AWS credentials.

1.  Build the example on **ARM** toolchain
    -   NuMaker-IoT-M467
        ```
        $ mbed compile -m NUMAKER_IOT_M467 -t ARM
        ```
    -   NuMaker-IoT-M487
        ```
        $ mbed compile -m NUMAKER_IOT_M487 -t ARM
        ```
    -   NuMaker-M2354
        ```
        $ mbed compile -m NU_M2354 -t ARM
        ```

1.  Append version suffix `_V1.0.0` to the built image file name for distinct from below.

    -   NuMaker-IoT-M467

        BUILD/NUMAKER_IOT_M467/ARM/`NuMaker-mbed-AWS-IoT-CSDK-OTA-example.bin` ??`NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0.bin`

    -   NuMaker-IoT-M487

        BUILD/NUMAKER_IOT_M487/ARM/`NuMaker-mbed-AWS-IoT-CSDK-OTA-example.bin` ??`NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0.bin`

    -   NuMaker-M2354

        BUILD/NU_M2354/ARM/`NuMaker-mbed-AWS-IoT-CSDK-OTA-example.bin` ??`NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0.bin`

    **NOTE**: For NuMaker-IoT-M467/NuMaker-IoT-M487, this file will be signed later.
    For NuMaker-IoT-M487/NuMaker-M2354, this file is for flash later.

1.  Sign application binary of first version `V1.0.0` (MCUboot only)

    -   NuMaker-IoT-M467
        ```
        $ imgtool sign \
        -k bootloader/MCUboot/signing-keys.pem \
        --align 4 \
        -v 1.0.0+0 \
        --header-size 4096 \
        --pad-header \
        -S 0x73000 \
        BUILD/NUMAKER_IOT_M467/ARM/NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0.bin \
        BUILD/NUMAKER_IOT_M467/ARM/NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0_signed.bin
        ```

    -   NuMaker-IoT-M487

        ```
        $ imgtool sign \
        -k bootloader/MCUboot/signing-keys.pem \
        --align 4 \
        -v 1.0.0+0 \
        --header-size 4096 \
        --pad-header \
        -S 0x66000 \
        BUILD/NUMAKER_IOT_M487/ARM/NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0.bin \
        BUILD/NUMAKER_IOT_M487/ARM/NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0_signed.bin
        ```

        **NOTE**: This file will be combined with MCUboot bootloader later.

        **NOTE**: Application version for MCUboot is `V1.0.0+0` and for AWS is `V1.0.0`.
        These two version numbers are made the same to be consistent.

        **NOTE**: `-S 0x73000`/`-S 0x66000` is to specify MCUboot primary/secondary slot size.

1.  Re-build the example with increasing version of the application.
    For example, set `APP_VERSION_MAJOR/MINOR/BUILD` in `configs/aws_config.h` to `1/0/1`.
    -   NuMaker-IoT-M467
        ```
        $ mbed compile -m NUMAKER_IOT_M467 -t ARM
        ```
    -   NuMaker-IoT-M487
        ```
        $ mbed compile -m NUMAKER_IOT_M487 -t ARM
        ```
    -   NuMaker-M2354
        ```
        $ mbed compile -m NU_M2354 -t ARM
        ```

1.  Append version suffix `_V1.0.1` to the built image file name for distinct from above.

    -   NuMaker-IoT-M467

        BUILD/NUMAKER_IOT_M467/ARM/`NuMaker-mbed-AWS-IoT-CSDK-OTA-example.bin` ??`NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1.bin`

    -   NuMaker-IoT-M487

        BUILD/NUMAKER_IOT_M487/ARM/`NuMaker-mbed-AWS-IoT-CSDK-OTA-example.bin` ??`NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1.bin`

    -   NuMaker-M2354

        BUILD/NU_M2354/ARM/`NuMaker-mbed-AWS-IoT-CSDK-OTA-example_update.bin` ??`NuMaker-mbed-AWS-IoT-CSDK-OTA-example_update_V1.0.1.bin`

        **NOTE**: For NuMaker-M2354, **DO** choose the built image file name having `_update` suffix. 

    **NOTE**: For NuMaker-IoT-M467/NuMaker-IoT-M487, this file will be signed later.
    For NuMaker-M2354, this file is for upload to AWS S3 bucket later.

1.  Sign application binary of second version `V1.0.1` (MCUboot only)

    -   NuMaker-IoT-M467
        ```
        $ imgtool sign \
        -k bootloader/MCUboot/signing-keys.pem \
        --align 4 \
        -v 1.0.1+0 \
        --header-size 4096 \
        --pad-header \
        -S 0x73000 \
        BUILD/NUMAKER_IOT_M467/ARM/NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1.bin \
        BUILD/NUMAKER_IOT_M467/ARM/NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1_signed.bin
        ```

    -   NuMaker-IoT-M487
        ```
        $ imgtool sign \
        -k bootloader/MCUboot/signing-keys.pem \
        --align 4 \
        -v 1.0.1+0 \
        --header-size 4096 \
        --pad-header \
        -S 0x66000 \
        BUILD/NUMAKER_IOT_M487/ARM/NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1.bin \
        BUILD/NUMAKER_IOT_M487/ARM/NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1_signed.bin
        ```

    **NOTE**: This file is for upload to AWS S3 bucket later.

1.  Combine MCUboot bootloader binary and signed application binary of first version `V1.0.0` (MCUboot only)

    -   NuMaker-IoT-M467
        ```
        $ srec_cat \
        bootloader/MCUboot/mbed-mcuboot-bootloader_m467-iot_flashiap.bin -Binary -offset 0x0 \
        BUILD/NUMAKER_IOT_M467/ARM/NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0_signed.bin -Binary -offset 0x10000 \
        -o BUILD/NUMAKER_IOT_M467/ARM/NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0_merged.hex -Intel
        ```

    -   NuMaker-IoT-M487
        ```
        $ srec_cat \
        bootloader/MCUboot/mbed-mcuboot-bootloader_m487-iot_spif.bin -Binary -offset 0x0 \
        BUILD/NUMAKER_IOT_M487/ARM/NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0_signed.bin -Binary -offset 0x10000 \
        -o BUILD/NUMAKER_IOT_M487/ARM/NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0_merged.hex -Intel
        ```

        **NOTE**: The combined file `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0_merged.hex` is for flash later.

        **NOTE**: `-offset 0x0` is to specify start address of MCUboot bootloader.

        **NOTE**: `-offset 0x10000` is to specify start address of primary slot where active application binary is located.

### Flash the image

-   NuMaker-IoT-M467

    Just drag-n-drop `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0_merged.hex` onto NuMaker-IoT-M467 board.

    **NOTE**: The operation above requires NuMaker-IoT-M467 board's Nu-Link2 switched to **MASS** mode (MSG to non-ON).

-   NuMaker-IoT-M487

    Just drag-n-drop `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0_merged.hex` onto NuMaker-IoT-M487 board.

    **NOTE**: The operation above requires NuMaker-IoT-M487 board's Nu-Link switched to **MASS** mode (MSG to ON).

-   NuMaker-M2354

    Just drag-n-drop `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0.bin` onto NuMaker-M2354 board.

    **NOTE**: The operation above requires NuMaker-M2354 board's Nu-Link2 switched to **MASS** mode (MSG to non-ON).

### Operations on AWS IoT Console

#### Prerequisites for the AWS Over-The-Air Update (OTA)

Prepare the prerequisites following [the guide](https://github.com/aws/aws-iot-device-sdk-embedded-C#prerequisites-for-the-aws-over-the-air-update-ota-demos).

#### Scheduling an OTA Update Job

Schedule an OTA Update job following [the guide](https://github.com/aws/aws-iot-device-sdk-embedded-C#scheduling-an-ota-update-job).

The following steaps are re-statements of above and adapted to this port:

1.  Go to the A[WS IoT Core console](http://console.aws.amazon.com/iot/).

1.  Manage ??Jobs ??Create ??Create a FreeRTOS OTA update job ??Select the corresponding name for your device from the thing list.

    **NOTE**: This port supports MQTT protocol only.

1.  Sign a new firmware ??Create a new profile ??Select any SHA-ECDSA signing platform ??Upload the code signing certificate [from prerequisites](#prerequisites-for-the-aws-over-the-air-update-ota) and provide its path on the device.

    **NOTE**: For **Pathname of code signing certificate on device**, set to PKCS #11 label `pkcs11configLABEL_CODE_VERIFICATION_KEY` defined at the file below.
    Its value could be `Code_Verify_Key` for example.

    -   NuMaker-IoT-M467: `mbed-client-for-aws/mbed/COMPONENT_AWSIOT_PKCS11/core_pkcs11_config.h`
    -   NuMaker-IoT-M487: `mbed-client-for-aws/mbed/COMPONENT_AWSIOT_PKCS11/core_pkcs11_config.h`
    -   NuMaker-M2354: `mbed-client-for-aws/mbed/COMPONENT_AWSIOT_PKCS11PSA/corePKCS11/core_pkcs11_config.h`

1.  Select the image ??Select the bucket you created during the [prerequisite steps](#prerequisites-for-the-aws-over-the-air-update-ota) ??Upload the binary
    -   NuMaker-IoT-M467: `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1_signed.bin`.
    -   NuMaker-IoT-M487: `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1_signed.bin`.
    -   NuMaker-M2354: `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_update_V1.0.1.bin`

1.  For **Pathname of file on device**, it is not used. Just set to below for example.
    -   NuMaker-IoT-M467: `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1_signed.bin`.
    -   NuMaker-IoT-M487: `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1_signed.bin`.
    -   NuMaker-M2354: `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_update_V1.0.1.bin`

1.  Select the IAM role created during the [prerequisite steps](#prerequisites-for-the-aws-over-the-air-update-ota).

1.  Create the Job.


### Monitor the application through host console

Configure host terminal program with **115200/8-N-1**, and you should see log similar to below:

Device not provisioned yet. Simulate the provision process:
-   NuMaker-IoT-M467/NuMaker-IoT-M487
```
The device has not provisioned yet. Try to provision it...
Provision for development...
Reset kvstore...
Reset kvstore...OK
Provision for development...OK
```
-   NuMaker-M2354
```
PROV: Install root CA certificate...
PROV: Install root CA certificate...OK
......
PROV: Install code verification public key...
PROV: Install code verification public key...OK
```

Application version before update should be `1.0.0`:
```
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1696] *** Application version: 1.0.0
```

Connect to AWS MQTT server:
```
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1697] Connecting to the network...
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1708] MAC: fc:f5:c4:a5:e7:93
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1709] Connection Success
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1712] Current heap: 852

[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1713] Max heap size: 3900

[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1714] Reserved heap size: 127856

[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1537] OTA over MQTT demo, Application version 1.0.0
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1058] Establishing a TLS session to a1fljoeglhtf61-ats.iot.us-east-2.amazonaws.com:8883.
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1203] Creating an MQTT connection to a1fljoeglhtf61-ats.iot.us-east-2.amazonaws.com.
......
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1166] MQTT connection successfully established with broker.
```

Go firmware OTA flow:
```
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:2838] Current State=[RequestingJob], Event=[Start], New state=[RequestingJob]
......
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota_mqtt.c:383] Subscribed to MQTT topic: $aws/things/Nuvoton-Mbed-D001/jobs/notify-next
......
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:2838] Current State=[WaitingForJob], Event=[RequestJobDocument], New state=[WaitingForJob]
......
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:2239] No active job available in received job document: OtaJobParseErr_t=OtaJobParseErrNoActiveJobs
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:2838] Current State=[WaitingForJob], Event=[ReceivedJobDocument], New state=[CreatingFile]
```

Receive a new OTA update job:
```
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:1645] Extracted parameter: [key: value]=[execution.jobId: AFR_OTA-ccli8-ota-update-job-097]
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:1645] Extracted parameter: [key: value]=[execution.jobDocument.afr_ota.streamname: AFR_OTA-d94c1d82-06ee-4530-8f7b-09e434991d24]
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:1645] Extracted parameter: [key: value]=[execution.jobDocument.afr_ota.protocols: ["MQTT"]]
```

-   NuMaker-IoT-M467
```
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:1645] Extracted parameter: [key: value]=[filepath: NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1_signed.bin]
```
-   NuMaker-IoT-M487
```
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:1645] Extracted parameter: [key: value]=[filepath: NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1_signed.bin]
```
-   NuMaker-M2354
```
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:1645] Extracted parameter: [key: value]=[filepath: NuMaker-mbed-AWS-IoT-CSDK-OTA-example_update_V1.0.1.bin]
```

```
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:1684] Extracted parameter: [key: value]=[filesize: 352698]
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:1684] Extracted parameter: [key: value]=[fileid: 0]
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:1645] Extracted parameter: [key: value]=[certfile: Code_Verify_Key]
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:1575] Extracted parameter [ sig-sha256-ecdsa: MEUCIQDRmJCcKm2S8hWJlzFANUAE3X9P... ]
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:2198] Job document was accepted. Attempting to begin the update.
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:2322] Job parsing success: OtaJobParseErr_t=OtaJobParseErrNone, Job name=AFR_OTA-ccli8-ota-update-job-097
```

Download started:
```
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:2463] Received valid file block: Block index=0, Size=2048
```

Download completed:
```
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:2632] Received final block of the update.
```

Verify code signature and prepare for firmware update:
-   NuMaker-IoT-M467/NuMaker-IoT-M487
```
[INFO] [MCUb] [.\mbed-client-for-aws\mbed\COMPONENT_AWSIOT_OTA\COMPONENT_AWSIOT_OTA_PAL_MCUBOOT\ota_pal_mcuboot.cpp:380] otaPal_WriteBlock(offset=407552, size=712, total=408264)...
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:2632] Received final block of the update.
[INFO] [MCUb] [.\mbed-client-for-aws\mbed\COMPONENT_AWSIOT_OTA\COMPONENT_AWSIOT_OTA_PAL_MCUBOOT\ota_pal_mcuboot.cpp:498] otaPal_CloseFile()...
[WARN] [MCUb] [.\mbed-client-for-aws\mbed\COMPONENT_AWSIOT_OTA\COMPONENT_AWSIOT_OTA_PAL_MCUBOOT\ota_pal_mcuboot.cpp:515] Ignore certificate file pathname Code_Verify_Key. Use predefined PKCS11 label Code_Verify_Key instead
[INFO] [MCUb] [.\mbed-client-for-aws\mbed\COMPONENT_AWSIOT_OTA\COMPONENT_AWSIOT_OTA_PAL_MCUBOOT\ota_pal_mcuboot.cpp:801] Code signature size: 70
[INFO] [MCUb] [.\mbed-client-for-aws\mbed\COMPONENT_AWSIOT_OTA\COMPONENT_AWSIOT_OTA_PAL_MCUBOOT\ota_pal_mcuboot.cpp:876] Code signature verification OK
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:2653] Received entire update and validated the signature.
```

-   NuMaker-M2354
```
[INFO] [PSAFWU] [.\mbed-client-for-aws\mbed\COMPONENT_AWSIOT_OTA\COMPONENT_AWSIOT_OTA_PAL_PSAFWU\ota_pal_psafwu.cpp:491] otaPal_CloseFile()...
[WARN] [PSAFWU] [.\mbed-client-for-aws\mbed\COMPONENT_AWSIOT_OTA\COMPONENT_AWSIOT_OTA_PAL_PSAFWU\ota_pal_psafwu.cpp:508] Ignore certificate file pathname Code_Verify_Key. Use predefined PKCS11 label Code_Verify_Key instead
[INFO] [PSAFWU] [.\mbed-client-for-aws\mbed\COMPONENT_AWSIOT_OTA\COMPONENT_AWSIOT_OTA_PAL_PSAFWU\ota_pal_psafwu.cpp:511] Code signature size: 71
[INFO] [PSAFWU] [.\mbed-client-for-aws\mbed\COMPONENT_AWSIOT_OTA\COMPONENT_AWSIOT_OTA_PAL_PSAFWU\ota_pal_psafwu.cpp:533] [INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1617] Code signature verification OK
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:2653] Received entire update and validated the signature.
```

Reboot:
-   NuMaker-IoT-M467/NuMaker-IoT-M487
```
[INFO] [MCUb] [.\mbed-client-for-aws\mbed\COMPONENT_AWSIOT_OTA\COMPONENT_AWSIOT_OTA_PAL_MCUBOOT\ota_pal_mcuboot.cpp:582] otaPal_ActivateNewImage()...
[INFO] [MCUb] [.\mbed-client-for-aws\mbed\COMPONENT_AWSIOT_OTA\COMPONENT_AWSIOT_OTA_PAL_MCUBOOT\ota_pal_mcuboot.cpp:564] System will reboot in 3 seconds...
```

-   NuMaker-M2354
```
[INFO] [PSAFWU] [.\mbed-client-for-aws\mbed\COMPONENT_AWSIOT_OTA\COMPONENT_AWSIOT_OTA_PAL_PSAFWU\ota_pal_psafwu.cpp:546] System will reboot in 3 seconds...
```

Reboot to bootloader for firmware update:
-   NuMaker-IoT-M467/NuMaker-IoT-M487
```
[INFO][BL]: Starting MCUboot
[INFO][MCUb]: Primary image: magic=unset, swap_type=0x1, copy_done=0x3, image_ok=0x3
[INFO][MCUb]: Scratch: magic=unset, swap_type=0x1, copy_done=0x3, image_ok=0x3
[INFO][MCUb]: Boot source: primary slot
[INFO][MCUb]: Swap type: test
[INFO][MCUb]: Starting swap using scratch algorithm.
[INFO][BL]: Booting firmware image at 0x11000
```

-   NuMaker-M2354
```
[INF] Starting bootloader
[INF] Swap type: none
[INF] Swap type: test
[INF] Image upgrade secondary slot -> primary slot
[INF] Erasing the primary slot
[INF] Copying the secondary slot to the primary slot: 0xzx bytes
[INF] Bootloader chainload address offset: 0x20000
[INF] Jumping to the first image slot
```

Reboot to application (updated):
-   NuMaker-IoT-M467/NuMaker-IoT-M487
```
The device has provisioned. Skip provision process
```

-   NuMaker-M2354
```
PROV: Install root CA certificate...
Has installed, SKIP
PROV: Install root CA certificate...OK
......
PROV: Install code verification public key...
Has installed, SKIP
PROV: Install code verification public key...OK
```

Application version after update should be `1.0.1`:
```
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1696] *** Application version: 1.0.1
```

Re-connect to AWS MQTT servier:
```
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1697] Connecting to the network...
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1708] MAC: fc:f5:c4:a5:e7:93
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1709] Connection Success
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1712] Current heap: 852

[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1713] Max heap size: 2787

[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1714] Reserved heap size: 127856

[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1537] OTA over MQTT demo, Application version 1.0.1
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1058] Establishing a TLS session to a1fljoeglhtf61-ats.iot.us-east-2.amazonaws.com:8883.
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1203] Creating an MQTT connection to a1fljoeglhtf61-ats.iot.us-east-2.amazonaws.com.
......
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1166] MQTT connection successfully established with broker.
```

Complete rest of firmware OTA:
-   NuMaker-IoT-M467/NuMaker-IoT-M487
```
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:794] Beginning self-test.
[INFO] [MCUb] [.\mbed-client-for-aws\mbed\COMPONENT_AWSIOT_OTA\COMPONENT_AWSIOT_OTA_PAL_MCUBOOT\ota_pal_mcuboot.cpp:622] otaPal_SetPlatformImageState(2)...
[INFO] [MCUb] [.\mbed-client-for-aws\mbed\COMPONENT_AWSIOT_OTA\COMPONENT_AWSIOT_OTA_PAL_MCUBOOT\ota_pal_mcuboot.cpp:694] otaPal_SetPlatformImageState(2)->2
```

-   NuMaker-M2354
```
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:794] Beginning self-test.
[INFO] [PSAFWU] [.\mbed-client-for-aws\mbed\COMPONENT_AWSIOT_OTA\COMPONENT_AWSIOT_OTA_PAL_PSAFWU\ota_pal_psafwu.cpp:616] otaPal_SetPlatformImageState(2)...
[INFO] [PSAFWU] [.\mbed-client-for-aws\mbed\COMPONENT_AWSIOT_OTA\COMPONENT_AWSIOT_OTA_PAL_PSAFWU\ota_pal_psafwu.cpp:695] otaPal_SetPlatformImageState(2)->2
```

### Walk through source code

#### AWS configuration (`configs/`)

AWS connection parameters and credentails are placed here.

#### Pre-main (`pre-main/`)

In Mbed OS boot sequence, `mbed_main()`, designed for user application override, is run before `main()`.
Here, it is used to run the following tasks:

1.  Simulate provision process for development (`provision/`)
    -   NuMaker-IoT-M467/NuMaker-IoT-M487 (`provision/COMPONENT_AWSIOT_PKCS11`)
        1.  Reset [KVStore](https://os.mbed.com/docs/mbed-os/v6.6/apis/kvstore.html)
        1.  Inject AWS credentials
        1.  Mark the device as provisioned
        ```
        The device has not provisioned yet. Try to provision it...
        Provision for development...
        Reset kvstore...
        Reset kvstore...OK
        Provision for development...OK
        ```

    -   NuMaker-M2354 (`provision/COMPONENT_AWSIOT_PKCS11PSA`)

        Inject AWS credentials through PSA Crypto/Storage API.
        
        ```
        PROV: Install root CA certificate...
        PROV: Install root CA certificate...OK
        ......
        PROV: Install code verification public key...
        PROV: Install code verification public key...OK
        ```

    **NOTE**: This function is for development requirement. Remove `provision/` directory for production.

1.  Set up event queue for dispatching host command (`host-stdin/`)

    Currently, press the following command:
    1.  `h` for printing heap statistics
        ```
        ** MBED HEAP STATS **
        **** current_size: 61830
        **** max_size    : 71866
        *****************************
        ```

    1.  `s` for printing stack statistics
        ```
        ** MBED THREAD STACK STATS **
        Thread: 0x20005718, Stack size: 2048, Max stack: 584
        Thread: 0x20008eac, Stack size: 4096, Max stack: 1144
        Thread: 0x20008864, Stack size: 512, Max stack: 64
        Thread: 0x200088ec, Stack size: 8192, Max stack: 3104
        Thread: 0x200088a8, Stack size: 768, Max stack: 96
        *****************************
        ```

    1.  `r` for resetting system
        ```
        System reset after 2 secs...
        ```

    **NOTE**: This function is for development requirement. Remove `host-stdin/` directory for production.

#### Main with firmware OTA over MQTT (`demo_ota_mqtt/ota_demo_core_mqtt.cpp`)

The example here is port of [SDK ota_demo_core_mqtt](https://github.com/aws/aws-iot-device-sdk-embedded-C/tree/main/demos/ota/ota_demo_core_mqtt) and shows firmware OTA with AWS IoT over MQTT.

-   NuMaker-IoT-M487

    **NOTE**: Disable write-protect and hold functions of on-board SPI flash.
              For re-designed board which has had /WP and ?HOLD pins pull-high,
              remove the code fragment below to spare these two GPIO pins.

    ```C++
    #if defined(TARGET_NUMAKER_PFM_M487) || defined(TARGET_NUMAKER_IOT_M487)
    DigitalOut onboard_spi_wp(PC_5, 1);
    DigitalOut onboard_spi_hold(PC_4, 1);
    #endif
    ```

### Implementation differences among targets

#### Provision AWS credentials

-   NuMaker-IoT-M467/NuMaker-IoT-M487
    -   Keys are stored in Mbed KVStore.
    -   Certificates are stored in Mbed KVStore.

-   NuMaker-M2354
    -   Keys are stored in TF-M through PSA Crypto API.
    -   Certificates are stored in TF-M through PSA Storage API.

#### Access to provisioned AWS credentials

-   NuMaker-IoT-M467/NuMaker-IoT-M487
    -   Keys are accessible to Mbed for TLS handshake.
    -   Certificates are accessible to Mbed for TLS handshake.

-   NuMaker-M2354
    -   Keys are inaccessible to Mbed and Mbed TLS wraps them as opaque for TLS handshake.
    -   Certificates are accessible to Mbed through PSA Storage API for TLS handshake.

#### Non-persistent keys

-   NuMaker-IoT-M467/NuMaker-IoT-M487: Generated through Mbed TLS's internal crypto functions and disclosed for crypto operations
-   NuMaker-M2354: Generated through PSA Crypto API and wrapped as opaque by Mbed TLS for crypto operations

#### PKCS11 library

-   NuMaker-IoT-M467/NuMaker-IoT-M487
    -   Software implementation backed by Mbed KVStore
    -   Do crypto operations using Mbed TLS's internal crypto functions
    -   Consistent with provisioned AWS credentials above

-   NuMaker-M2354
    -   Hardware implementation enabled by PSA Crypto/Storage API
    -   Do crypto operations through PSA Crypto API
    -   Consistent with provisioned AWS credentials above

#### Bootloader

-   NuMaker-IoT-M467/NuMaker-IoT-M487: MCUboot

    **NOTE**: To re-create the pre-built bootloader binary `mbed-mcuboot-bootloader_m467-iot_flashiap.bin`/`mbed-mcuboot-bootloader_m487-iot_spif.bin`,
    follow [Nuvoton quick-start](https://github.com/OpenNuvoton/mbed-mcuboot-demo/NUVOTON_QUICK_START.md),
    with target name being `NUMAKER_IOT_M467_FLASHIAP`/`NUMAKER_IOT_M487_SPIF`.

    **NOTE**: To change attached signing keys `signing-keys.pem`/`signing_keys.c` for production,
    follow [change signing keys](https://github.com/OpenNuvoton/mbed-mcuboot-demo/NUVOTON_QUICK_START.md#changing-signing-keys),
    to re-create signing keys and update them in both `mbed-mcuboot-demo` and `NuMaker-mbed-AWS-IoT-CSDK-OTA-example` repositories.

-   NuMaker-M2354: TF-M integrated MCUboot

#### AWS OTA PAL

-   NuMaker-IoT-M467
    -   Store firmware candidate in internal flash
    -   Consistent with above bootloader

-   NuMaker-IoT-M487
    -   Store firmware candidate in SPI flash
    -   Consistent with above bootloader

-   NuMaker-M2354
    -   Store firmware candidate in TF-M SD card through PSA Firmware Upgrade API
    -   Consistent with above bootloader

## Breaking changes

This section lists major changes in `master` branch.

-   Upgrade AWS C-SDK from 202012.01 to 202108.00

    Refer to [AWS C-SDK releases](https://github.com/aws/aws-iot-device-sdk-embedded-C#releases-and-documentation) for their release notes.

    **NOTE**: For legacy C-SDK 202012.01 port, check out the `nuvoton_legacy_csdk_202012.01` branch.

-   For M487, change OTA PAL from proprietary bootloader to MCUboot

    **NOTE**: For legacy OTA PAL associated with proprietary bootloader, check out the `proprietary_boot` branch.

    **NOTE**: Compared to proprietary bootloader, MCUboot can increase ROM footprint by 45KiB in total.
    Try to change compiler option e.g. add `NDEBUG` macro to optimize code size.

-   Provisions for different targets are distinguished by `COMPONENT_AWSIOT_PKCS11`/`COMPONENT_AWSIOT_PKCS11PSA`.

-   Changes to `demo_ota_mqtt/ota_demo_core_mqtt.cpp`

    -   Base on 202108.00 [ota_demo_core_mqtt](https://github.com/aws/aws-iot-device-sdk-embedded-C/tree/main/demos/ota/ota_demo_core_mqtt).
    -   Remove the workaround to `OtaTimerInterface_t` having C++ keyword `delete` as member name, which now fixes to `deleteTimer` in updated C-SDK.

-   Resolve inconsistency with null-terminated string for PEM credentials

    mbedtls API requires PEM be null-terminated string.
    For this requirement and consistency, we have the following rules:

    -   All in-ram and in-storage PEM must be null-terminated string, size of which will include the `\0` character.
    -   In provision for PEM, its ending `\0` character is stored and so its size counts the character.
    -   In fetch from storage for PEM, data and size through `kv_get()`/`kv_get_info()` or `psa_ps_get()`/`psa_ps_get_info()` will include the ending `\0` character.
    -   Now that the PEM has been null-terminated, it can pass to mbedtls API straight.
    -   To make credential pass-along code format-agnostic (PEM or DER), credential pass-along interface (`aws::credentials::provision` and `CredentialInfo_t`) add one additional `size` parameter.

## Limitations

-   For NuMaker-M2354, no support for firmware upgrade rollback currently.
-   For NuMaker-M2354, it is [TF-M](https://www.trustedfirmware.org/projects/tf-m/)-enabled and all crypto keys should be confidential, non-disclosed to NSPE world.
    These all are true, except AWS device (private) key being RSA.
    This is because [current Mbed TLS](https://github.com/ARMmbed/mbed-os/blob/4cfbea43cabe86bc3ed7a5287cd464be7a218938/connectivity/mbedtls/source/pk.c#L169-L171) just supports ECC as opaque.
