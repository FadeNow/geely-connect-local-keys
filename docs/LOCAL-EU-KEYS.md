# European app support with local keys

This experimental variant requires each owner to supply the European app
identity locally. It does not ship the five European signing/encryption values,
an APK, native libraries, encrypted copies of those values, or a download URL
for a prepared key file. There is no server that supplies them.

The original project's **legacy and SEA implementations still contain their
existing protocol constants**. This change removes the need to distribute the
new European material; it is not a claim that the entire upstream project has
no embedded constants, or a guarantee about legal rights. Use only an app copy
you are entitled to analyze. Obtaining values yourself does not automatically
authorize every use or redistribution.

## 1. Obtain your own installed Android app

The included optional extraction tool supports only **com.geely.global 1.1.1,
ARM64 Android**. It does not support iPhone or assume that another Android
release has the same layout.

Copy the installed APK files using an Android package-export tool you trust,
or Android's official platform tools on your own phone. With an explicitly
authorized debugging connection, this read-only command lists the installed
package paths:

```sh
adb shell pm path com.geely.global
```

Copy the returned `base.apk` and `split_config.arm64_v8a.apk` paths with
`adb pull`, removing the leading `package:` from each path. Copying an APK does
not require copying private app data or logging in to the app. Afterwards,
revoke the debugging connection and disable debugging if you enabled it only
for this purpose. Do not upload the APKs to this repository.

## 2. Run the optional extractor yourself, on your computer

Python 3.12 was used for validation on macOS. From this repository:

```sh
python3 -m venv .venv-eu-keys
.venv-eu-keys/bin/python -m pip install -r tools/eu-key-requirements.txt
.venv-eu-keys/bin/python tools/extract_eu_keys.py \
  --base-apk /path/to/your/base.apk \
  --arm64-apk /path/to/your/split_config.arm64_v8a.apk \
  --output /private/path/geely_eu_app_keys.json
```

On Windows, use `.venv-eu-keys\Scripts\python.exe` and the corresponding
Windows paths. Only macOS has been exercised so far.

The extraction itself is offline. Dependency installation requires access to
the Python package registry. No Geely account, password, email, vehicle data
or phone connection is used by the extractor. It reads the owner's APKs,
emulates the library getters in isolated memory and authenticates the decoded
regional values. Unsupported imports or mismatched data fail; no native
library is loaded for execution by the host OS.

The output is created with mode `0600` on POSIX systems and is never printed.
The tool refuses to overwrite an existing file or symbolic link. On systems
without POSIX permission semantics, protect the file with the OS's normal
file-access controls.

The five JSON fields are:

| Field | Meaning |
| --- | --- |
| `hmac_access_key` | EU application identity |
| `hmac_secret` | EU identity-service signing material |
| `snc_secret` | EU vehicle-gateway signing material |
| `vin_key_hex` | Original AES key bytes, encoded as hexadecimal |
| `vin_iv_hex` | Original AES IV bytes, encoded as hexadecimal |

There are intentionally no working example values. A key that looks like hex
text must first be interpreted as the original bytes; the extractor handles
that distinction.

If you use your own analysis process instead, produce this same JSON shape.
The reference points for this build are `ServerUtils` with PROD/OVERSEAS,
and the `GEELY / EU / PROD` entries of `tj/i` methods `d`, `e`, and `f`.
No extractor, key file, or external service is run automatically by HA.

## 3. Place the file in Home Assistant

Copy `geely_eu_app_keys.json` into the Home Assistant configuration directory,
alongside `configuration.yaml` (normally `/config/geely_eu_app_keys.json`).
Use a private transfer method. Restrict access to the HA user and keep the
file out of public shares and source control.

Install this variant through HACS as the custom integration repository
`FadeNow/geely-connect-local-keys`, choose its release, and restart HA.
It uses the same `geely_connect` integration directory as the original:
install one variant at a time.

In setup, select **Geely / Geely EM app (Europe / SEA)** and the country of
your account. EU routing applies to ES, GB, FR, HU, MD, DE, NL, BE and LU.
Enter your account email/password directly in HA. Manual polling and leaving
password storage unchecked are suitable for an initial discovery test.

Missing or invalid app keys stop setup **before any login request**. On a
restart, an existing EU entry remains unavailable with an actionable setup
error until a valid local file is present. There is no fallback to embedded
EU keys or to SEA servers.

The file is loaded for setup, reauthentication and restored entries. The same
in-memory profile is used for session renewal. After replacing the file,
reload the integration or restart HA to load the new values.

## Storage and sharing

The app keys stay in the local file and in runtime memory. They are not copied
into the integration's config entry or diagnostics. Their field names are
also covered by redaction, and the profile's representation hides the values.
The JSON file is not encrypted by this feature; Home Assistant backups may
include it, so protect those backups too.

Never attach the generated JSON, APKs, native libraries or private analysis
outputs to an issue or PR. `.gitignore` excludes these common filenames, but
it is not a substitute for checking the files you publish.

## Validation and scope

The routing and protocol behavior were used successfully by a European E2
owner in a preceding experimental build. This local-file variant has not
been installed in that owner's working HA instance.

Validation of this variant includes fake-key login/discovery/renewal tests,
local-file validation, failure before networking when keys are absent,
redaction and isolation between installations. Its extractor was run against
an owner's authorized local 1.1.1 APK copy; all five values matched the working
profile without printing or including them in the repository.

This repository starts from the original upstream project, not from the
earlier experimental fork's commits or releases. Creating it does not remove
material already published elsewhere.
