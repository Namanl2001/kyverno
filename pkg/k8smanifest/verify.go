package k8smanifest

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/ghodss/yaml"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	k8ssigutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func verify(manifestPath, keyPath string) {
	manifest, err := ioutil.ReadFile(manifestPath)
	// fmt.Printf("%s", manifest)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}

	vo := &k8smanifest.VerifyManifestOption{}
	// add signature/message/others annotations to ignore fields
	vo.SetAnnotationIgnoreFields()

	// // annotations := k8ssigutil.GetAnnotationsInYAML(manifest)
	// // imageRefAnnotationKey := vo.AnnotationConfig.ImageRefAnnotationKey()
	// // annoImageRef, annoImageRefFound := annotations[imageRefAnnotationKey]

	vo.KeyPath = keyPath

	objManifests := k8ssigutil.SplitConcatYAMLs(manifest)
	verified := false
	verifiedCount := 0
	signerName := ""
	diffMsg := ""
	var reterr error
	for _, objManifest := range objManifests {
		result, verr := k8smanifest.VerifyManifest(objManifest, vo)
		if verr != nil {
			reterr = verr
			break
		}
		if result != nil {
			if result.Verified {
				signerName = result.Signer
				verifiedCount += 1
			} else if result.Diff != nil && result.Diff.Size() > 0 {
				var obj unstructured.Unstructured
				_ = yaml.Unmarshal(objManifest, &obj)
				kind := obj.GetKind()
				name := obj.GetName()
				diffMsg = fmt.Sprintf("Diff found in %s %s, diffs:%s", kind, name, result.Diff.String())
				break
			}
		}
	}
	if verifiedCount == len(objManifests) {
		verified = true
	}
	if verified {
		if signerName == "" {
			fmt.Printf("verifed: %s", strconv.FormatBool(verified))
		} else {
			fmt.Printf("verifed: %s, signerName: %s", strconv.FormatBool(verified), signerName)
		}
	} else {
		errMsg := ""
		if reterr != nil {
			errMsg = reterr.Error()
		} else {
			errMsg = diffMsg
		}
		fmt.Printf("verifed: %s, error: %s", strconv.FormatBool(verified), errMsg)
	}
	fmt.Println()
}
