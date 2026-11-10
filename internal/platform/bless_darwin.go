//go:build darwin && cgo

package platform

/*
#cgo darwin LDFLAGS: -framework ServiceManagement -framework Security -framework CoreFoundation
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <ServiceManagement/ServiceManagement.h>
#include <stdlib.h>

static int blessHelper(const char *helperID, char **outErrMsg) {
    AuthorizationItem authItem = { kSMRightBlessPrivilegedHelper, 0, NULL, 0 };
    AuthorizationRights authRights = { 1, &authItem };
    AuthorizationFlags flags = kAuthorizationFlagDefaults |
                               kAuthorizationFlagInteractionAllowed |
                               kAuthorizationFlagPreAuthorize |
                               kAuthorizationFlagExtendRights;

    AuthorizationRef authRef = NULL;
    OSStatus status = AuthorizationCreate(&authRights, kAuthorizationEmptyEnvironment, flags, &authRef);
    if (status != errAuthorizationSuccess) {
        *outErrMsg = strdup("Authorization denied or cancelled by user");
        return (int)status;
    }

    CFStringRef label = CFStringCreateWithCString(kCFAllocatorDefault, helperID, kCFStringEncodingUTF8);
    CFErrorRef error = NULL;
    Boolean success = SMJobBless(kSMDomainSystemLaunchd, label, authRef, &error);
    CFRelease(label);
    AuthorizationFree(authRef, kAuthorizationFlagDefaults);

    if (!success) {
        if (error != NULL) {
            CFStringRef desc = CFErrorCopyDescription(error);
            if (desc != NULL) {
                char buffer[512];
                if (CFStringGetCString(desc, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
                    *outErrMsg = strdup(buffer);
                }
                CFRelease(desc);
            }
            CFRelease(error);
        }
        if (*outErrMsg == NULL) {
            *outErrMsg = strdup("SMJobBless failed");
        }
        return -1;
    }

    return 0;
}
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"
)

// BlessPrivilegedHelper initiates the native macOS authorization prompt via SMJobBless
// to install and activate com.cerberus.helper. The prompt is the system-managed
// Touch ID / Apple Watch / administrator-password dialog.
func BlessPrivilegedHelper(helperID string) error {
	if helperID == "" {
		helperID = "com.cerberus.helper"
	}

	// SMJobBless resolves the helper from the calling app's bundle, so fail with an
	// actionable message instead of an opaque launchd error when it is missing.
	if exe, err := os.Executable(); err == nil {
		contents := filepath.Dir(filepath.Dir(exe)) // .../Cerberus.app/Contents
		helperPath := filepath.Join(contents, "Library", "LaunchServices", helperID)
		if _, statErr := os.Stat(helperPath); statErr != nil {
			return fmt.Errorf("SMJobBless helper missing at %s: build it with scripts/build_helper_macos.sh and place it in Contents/Library/LaunchServices", helperPath)
		}
	}

	cHelper := C.CString(helperID)
	defer C.free(unsafe.Pointer(cHelper))

	var cErrMsg *C.char
	res := C.blessHelper(cHelper, &cErrMsg)
	if res != 0 {
		var errMsg string
		if cErrMsg != nil {
			errMsg = C.GoString(cErrMsg)
			C.free(unsafe.Pointer(cErrMsg))
		} else {
			errMsg = fmt.Sprintf("OSStatus %d", res)
		}
		return fmt.Errorf("privileged helper installation failed: %s", errMsg)
	}

	return nil
}
