package cmd

import (
	"codes.test/dp/registry"
	"encoding/base64"
	"fmt"
	"github.com/spf13/cobra"
	"log"
	"os"
	"strings"
	"time"
)

var (
	//strict bool
	saveName string
	username string
	password string
	harborToken string
)
var pullCmd = &cobra.Command{
	Use:     "pull",
	Aliases: []string{"p"},
	Short:   "pull images",
	Long: `
pull all images and write to a tar.gz file without docker daemon.`,
	Example: `
# pull a image or set the name to save
dp pull nginx:alpine
dp pull -o nginx.tar.gz nginx:alpine

# pull image use sha256
dp pull mcr.microsoft.com/windows/nanoserver@sha256:ae443bd9609b9ef06d21d6caab59505cb78f24a725cc24716d4427e36aedabf2

# pull images and set the name to save
dp pull -o project.tar.gz nginx:alpine nginx:1.17.5-alpine-perl

# pull from different registry 
dp pull -o project.tar.gz nginx:alpine gcr.io/google_containers/pause-amd64:3.1

# pull from private registry 
dp pull -o project.tar.gz private.registry.com/pause-amd64:3.1 -u username -p password
`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			_ = cmd.Help()
			return
		}
		if len(args) == 1 && saveName == "" {
			saveName = strings.ReplaceAll(args[0], "/", "_")
			saveName = fmt.Sprintf("%s.tar.gz", strings.Replace(saveName, ":", "@", 1))
		}
		// todo regex check
		//for _, name := range args {
		//https://github.com/docker/distribution/blob/master/reference/regexp.go
		//}
		if saveName == "" {
			saveName = fmt.Sprintf("%s.tar.gz", time.Now().Format("2006-1-2-15:04:05"))
		}
		if username != "" && password != "" {
			harborToken = encode(username, password)
		}
		if err := registry.Save(args, saveName, harborToken);err != nil {
			_ = os.Remove(saveName)
			log.Fatal("Save failed: ", err)
		}
		log.Printf("Successfully written to file %s", saveName)

	},
}

func init() {
	rootCmd.AddCommand(pullCmd)
	//cpCmd.Flags().BoolVarP(&strict, "strict-mode", "s", false,
	//	"The image name of the pull is strictly checked. If it is wrong, it will not be pulled.")
	pullCmd.Flags().StringVarP(&saveName, "out-file", "o", "", "the name will write to,default use timeformat")
	pullCmd.Flags().StringVarP(&username, "username", "u", "admin", "the login name with harbor")
	pullCmd.Flags().StringVarP(&password, "password", "p", "", "the password with harbor")
}

// 生成认证秘钥
func encode(username string, password string) string {
	input := []byte(username + ":" + password)
	encodeString := base64.StdEncoding.EncodeToString(input)
	encodeString = "Basic " + encodeString
	return encodeString
}
