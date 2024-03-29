# Example for Firmware OTA with AWS IoT on Nuvoton's Mbed Enabled boards

This is an example to show firmware Over-The-Air (OTA) with [AWS IoT service](https://aws.amazon.com/console/) on Nuvoton's Mbed Enabled boards.
It relies on the following modules:

-   [Mbed OS](https://github.com/ARMmbed/mbed-os):
    Is an open source embedded operating system designed specifically for the "things" in the Internet of Things.
-   [AWS IoT SDK port for Mbed OS](https://github.com/OpenNuvoton/mbed-client-for-aws/):
    Provides the port of the AWS IoT SDK for Mbed OS. It can be used to connect devices running Mbed OS to the AWS IoT Core service over MQTT.

## Support targets

Platform                                                                    |  Connectivity     | Storage for firmware OTA                  
----------------------------------------------------------------------------|-------------------|-------------------------------------------
[NuMaker-PFM-M487](https://developer.mbed.org/platforms/NUMAKER-PFM-M487/)  | Ethernet          | SPI flash                                 
[NuMaker-IoT-M487](https://os.mbed.com/platforms/NUMAKER-IOT-M487/)         | Wi-Fi ESP8266     | SPI flash                                 
[NuMaker-M2354](https://os.mbed.com/platforms/NUMAKER-M2354/)               | Wi-Fi ESP8266     | SD card                                   

## Support development tools

-   [Arm's Mbed Online Compiler](https://os.mbed.com/docs/mbed-os/v6.6/tools/developing-mbed-online-compiler.html)

    **NOTE**: Not support for NuMaker-M2354
-   [Arm's Mbed Studio](https://os.mbed.com/docs/mbed-os/v6.15/build-tools/mbed-studio.html)
-   [Arm's Mbed CLI 2](https://os.mbed.com/docs/mbed-os/v6.15/build-tools/mbed-cli-2.html)
-   [Arm's Mbed CLI 1](https://os.mbed.com/docs/mbed-os/v6.15/tools/developing-mbed-cli.html)

## Developer guide

This section is intended for developers to get started, import the example application, compile with Mbed CLI 1, and get it running firmware OTA with AWS IoT service.

### Hardware requirements

-   [NuMaker-IoT-M487](https://os.mbed.com/platforms/NUMAKER-IOT-M487/)
-   [NuMaker-M2354](https://os.mbed.com/platforms/NUMAKER-M2354/)

**NOTE**: Choose either one as example board

### Software requirements

-   [Arm's Mbed CLI 1](https://os.mbed.com/docs/mbed-os/v6.15/tools/developing-mbed-cli.html)
-   [NuMicro ICP Programming Tool](https://www.nuvoton.com/tool-and-software/software-development-tool/programmer/)

    **NOTE**: Needed for flashing onto NuMaker-IoT-M487 board

### Hardware setup

-   Firmware candidate storage
    -   NuMaker-IoT-M487: On-board SPI flash
    -   NuMaker-M2354: Micro SD card plugged-in
-   Switch target board
    -   NuMaker-IoT-M487's Nu-Link: TX/RX/VCOM to ON, MSG to non-ON
    -   NuMaker-M2354's Nu-Link2: TX/RX/VCOM to ON, MSG to non-ON
-   Connect target board to host through USB
    -   NuMaker-IoT-M487: No Mbed USB drive shows up in File Browser.
    -   NuMaker-M2354: Mbed USB drive shows up in File Browser.

### Compile with Mbed CLI 1

In the following, we take NuMaker-IoT-M487 or NuMaker-M2354 as example board to show this example.

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
    In `mbed_app.json`, configure WiFi **SSID**/**PASSWORD**.
    ```json
        "nsapi.default-wifi-ssid"                   : "\"SSID\"",
        "nsapi.default-wifi-password"               : "\"PASSWORD\"",
    ```

1.  In `configs/aws_config.h`, provide AWS connection parameters: **AWS_IOT_ENDPOINT**, **CLIENT_IDENTIFIER**, and **THING_NAME**.

1.  In `configs/aws_credentials.c`, provide relevant AWS credentials.

1.  Build the example on **ARM** toolchain
    -   NuMaker-IoT-M487
        ```
        $ mbed compile -m NUMAKER_IOT_M487 -t ARM
        ```
    -   NuMaker-M2354
        ```
        $ mbed compile -m NU_M2354 -t ARM
        ```

    Add version suffix `_V1.0.0` to the built image file name for distinct from below. This file is for flash later.

    -   NuMaker-IoT-M487

        BUILD/NUMAKER_IOT_M487/ARM/`NuMaker-mbed-AWS-IoT-CSDK-OTA-example.bin` → `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0.bin`

    -   NuMaker-M2354

        BUILD/NU_M2354/ARM/`NuMaker-mbed-AWS-IoT-CSDK-OTA-example.bin` → `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0.bin`

1.  Re-build the example with increasing version of the application.
    For example, set `APP_VERSION_MAJOR/MINOR/BUILD` in `configs/aws_config.h` to `1/0/1`.
    -   NuMaker-IoT-M487
        ```
        $ mbed compile -m NUMAKER_IOT_M487 -t ARM
        ```
    -   NuMaker-M2354
        ```
        $ mbed compile -m NU_M2354 -t ARM
        ```

    Add version suffix `_V1.0.1` to the built image file name for distinct from above. This file is for upload to AWS S3 bucket later.

    -   NuMaker-IoT-M487

        BUILD/NUMAKER_IOT_M487/ARM/`NuMaker-mbed-AWS-IoT-CSDK-OTA-example.bin` → `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1.bin`

    -   NuMaker-M2354

        BUILD/NU_M2354/ARM/`NuMaker-mbed-AWS-IoT-CSDK-OTA-example_update.bin` → `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_update_V1.0.1.bin`

        **NOTE**: Can only choose the built image file name having `_update` suffix. 

### Flash the images

-   NuMaker-IoT-M487

    1.  Open **NuMicro ICP Programming Tool** → Select **M480 Series** → Connect

    1.  Flash LDROM bootloader image into LDROM:

        In **Load File** group, click **LDROM** and select `bootloader/Bootloader_LDROM.bin` file
        → In **Programming** group, check only **LDROM** option → Start
    1.  Flash application image into APROM `0x0`:

        In **Load File** group, click **APROM**, select `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0.bin` file, and set **Offset** to `0x0`
        → In **Programming** group, check only **APROM** option → Start

    1.  Flash Cloner bootloader image into ARPOM `0x72000`:

        In **Load File** group, click **APROM**, select `bootloader/Bootloader_Cloner.bin` file, and set **Offset** to `0x72000`
        → In **Programming** group, check only **APROM** option → Start

    **NOTE**: The operatioins above require NuMaker-IoT-M487 board's Nu-Link swiched to **ICE** mode (MSG to non-ON).

    **NOTE**: The order of flashing application image and Cloner bootloader image is significant. This tool will erase all the blocks starting from the one the start address is located to the end.

-   NuMaker-M2354

    Just drag-n-drop `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0.bin` onto NuMaker-M2354 board.

    **NOTE**: The operatioins above require NuMaker-M2354 board's Nu-Link2 swiched to **MASS** mode (MSG to non-ON).

### Operations on AWS IoT Console

#### Prerequisites for the AWS Over-The-Air Update (OTA)

Prepare the prerequisites following [the guide](https://github.com/aws/aws-iot-device-sdk-embedded-C#prerequisites-for-the-aws-over-the-air-update-ota-demos).

#### Scheduling an OTA Update Job

Schedule an OTA Update job following [the guide](https://github.com/aws/aws-iot-device-sdk-embedded-C#scheduling-an-ota-update-job).

The following steaps are re-statements of above and adapted to this port:

1.  Go to the A[WS IoT Core console](http://console.aws.amazon.com/iot/).

1.  Manage → Jobs → Create → Create a FreeRTOS OTA update job → Select the corresponding name for your device from the thing list.

    **NOTE**: This port supports MQTT protocol only.

1.  Sign a new firmware → Create a new profile → Select any SHA-ECDSA signing platform → Upload the code signing certificate [from prerequisites](#prerequisites-for-the-aws-over-the-air-update-ota) and provide its path on the device.

    **NOTE**: For **Pathname of code signing certificate on device**, set to PKCS #11 label `pkcs11configLABEL_CODE_VERIFICATION_KEY` defined at the file below.
    Its value could be `Code_Verify_Key` for example.

    -   NuMaker-IoT-M487: `mbed-client-for-aws/mbed/COMPONENT_AWSIOT_PKCS11/core_pkcs11_config.h`
    -   NuMaker-M2354: `mbed-client-for-aws/mbed/COMPONENT_AWSIOT_PKCS11PSA/corePKCS11/core_pkcs11_config.h`

1.  Select the image → Select the bucket you created during the [prerequisite steps](#prerequisites-for-the-aws-over-the-air-update-ota) → Upload the binary
    -   NuMaker-IoT-M487: `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1.bin`.
    -   NuMaker-M2354: `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_update_V1.0.1.bin`

1.  For **Pathname of file on device**, it is not used. Just set to below for example.
    -   NuMaker-IoT-M487: `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1.bin`.
    -   NuMaker-M2354: `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_update_V1.0.1.bin`

1.  Select the IAM role created during the [prerequisite steps](#prerequisites-for-the-aws-over-the-air-update-ota).

1.  Create the Job.


### Monitor the application through host console

Configure host terminal program with **115200/8-N-1**, and you should see log similar to below:

Device not provisioned yet. Simulate the provision process:
-   NuMaker-IoT-M487
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

-   NuMaker-IoT-M487
```
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:1645] Extracted parameter: [key: value]=[filepath: NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1.bin]
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
-   NuMaker-IoT-M487
```
[prvPAL_CheckFileSignature] Started sig-sha256-ecdsa signature verification, file: Code_Verify_Key
[prvPAL_ReadAndAssumeCertificate] Using cert with label: Code_Verify_Key OK
[otaPal_CloseFile] sig-sha256-ecdsa signature verification passed.
[prvContextUpdateImageHeaderAndTrailer] OTA Sequence Number: 21
[prvContextUpdateImageHeaderAndTrailer] Image - Start: 0x00000000, End: 0x0005713f
[prvContextUpdateImageHeaderAndTrailer] Writing Trailer at: 0x00071000
[otaPal_CloseFile] Image header updated.
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:2600] Received entire update and validated the signature.
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
-   NuMaker-IoT-M487
```
[otaPal_ActivateNewImage] Activating the new MCU image.
[otaPal_ResetDevice] Resetting the device.
```

-   NuMaker-M2354
```
[INFO] [PSAFWU] [.\mbed-client-for-aws\mbed\COMPONENT_AWSIOT_OTA\COMPONENT_AWSIOT_OTA_PAL_PSAFWU\ota_pal_psafwu.cpp:546] System will reboot in 3 seconds...
```

Reboot to bootloader for firmware update:
-   NuMaker-IoT-M487
```
Boot from LDROM successful
read Magic code: @AFRTOS
Jump to APROM Cloner
Will boot from 0x00072000
SPIM get JEDEC ID=0xEF, 0x40, 0x16
Boot to AWS Cloner
read Magic code     : @AFRTOS
read Image flag     : 0xFF
read Sequence Num   : 0x00000015
read Start addr     : 0x00000000
read End addr       : 0x0005713F
read Exec addr      : 0x00000000
read Hardware ID    : 0x2000AAB4
read Reserved data  : 0x200011D8
Check OTA image success
Clone OTA image from SPI Flash to APROM
page_num: 0x58
Erasing APROM ...
Erasing page_num = 0x0
Erasing page_num = 0x1000
......
Erasing page_num = 0x56000
Erasing page_num = 0x57000
Clone APROM ...
Clone done.
Checksum OK. CRC32: 0x0
Update OTA header ...
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
-   NuMaker-IoT-M487
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
-   NuMaker-IoT-M487
```
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota.c:794] Beginning self-test.
[otaPal_GetPlatformImageState] image state [1] -- Flag[0xfe].
[otaPal_SetPlatformImageState] Accepted and committed final image.
[otaPal_SetPlatformImageState] image state [2] ---Flag[0xfc].
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
    -   NuMaker-IoT-M487 (`provision/COMPONENT_AWSIOT_PKCS11`)
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

The examplle here is port of [SDK ota_demo_core_mqtt](https://github.com/aws/aws-iot-device-sdk-embedded-C/tree/main/demos/ota/ota_demo_core_mqtt) and shows firmware OTA with AWS IoT over MQTT.

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

-   NuMaker-IoT-M487
    -   Keys are stored in Mbed KVStore.
    -   Certificates are stored in Mbed KVStore.

-   NuMaker-M2354
    -   Keys are stored in TF-M through PSA Crypto API.
    -   Certificates are stored in TF-M through PSA Storage API.

#### Access to provisioned AWS credentials

-   NuMaker-IoT-M487
    -   Keys are accessible to Mbed for TLS handshake.
    -   Certificates are accessible to Mbed for TLS handshake.

-   NuMaker-M2354
    -   Keys are inaccessible to Mbed and Mbed TLS wraps them as opaque for TLS handshake.
    -   Certificates are accessible to Mbed through PSA Storage API for TLS handshake.

#### Non-persistent keys

-   NuMaker-IoT-M487: Generated through Mbed TLS's internal crypto functions and disclosed for crypto operations
-   NuMaker-M2354: Generated through PSA Crypto API and wrapped as opaque by Mbed TLS for crypto operations

#### PKCS11 library

-   NuMaker-IoT-M487
    -   Software implementation backed by Mbed KVStore
    -   Do crypto operations using Mbed TLS's internal crypto functions
    -   Consistent with provisioned AWS credentials above

-   NuMaker-M2354
    -   Hardware implementation enabled by PSA Crypto/Storage API
    -   Do crypto opertions through PSA Crypto API
    -   Consistent with provisioned AWS credentials above

#### Bootloader

-   NuMaker-IoT-M487: Custom bootloader

-   NuMaker-M2354: TF-M integrated MCUboot

#### AWS OTA PAL

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
