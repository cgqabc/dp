package cmd

import (
	"dp/registry"
	"github.com/spf13/cobra"
	"log"
	"os"
)

var (
	//strict bool
	secpath string
	uname string
	pd string
	despath string
)
var transCmd = &cobra.Command{
	Use:     "trans",
	Aliases: []string{"t"},
	Short:   "trans images",
	Long: `
version v0.1
trans  images from regdit to others.`,
	Example: `
# trans a image 
dp trans -u admin -p 123456 -s registry.test.com/k8s/flannel:v0.10.0-amd64  -d 172.18.0.52/test/flannel:v0.10.0-amd64
`,
	Run: func(cmd *cobra.Command, args []string) {
		//if len(args) == 0 {
		//	_ = cmd.Help()
		//	return
		//}
        // pull image
     	saveFile := "tmp.tgz"
		if uname != "" && pd != "" {
			harborToken = encode(uname, pd)
		}
		secPaths := []string{secpath}

		if err := registry.Save(secPaths, saveFile, harborToken);err != nil {
			_ = os.Remove(saveFile)
			log.Fatal("Save failed: ", err)
		}
		log.Printf("Successfully pull images %s", secpath)

        //push image
		dPusher := registry.Dockerpush{
			TagUrl:    despath,
			ImagePath: saveFile,
			User:  uname,
			PassWd:    pd,
		}
		dPusher.Pusher()


	},
}

func init() {
	rootCmd.AddCommand(transCmd)
	//cpCmd.Flags().BoolVarP(&strict, "strict-mode", "s", false,
	//	"The image name of the trans is strictly checked. If it is wrong, it will not be transed.")
	transCmd.Flags().StringVarP(&secpath, "secpath", "s", "", "the image for pull")
	transCmd.Flags().StringVarP(&uname, "username", "u", "admin", "the login name with harbor")
	transCmd.Flags().StringVarP(&pd, "password", "p", "", "the password with harbor")
	transCmd.Flags().StringVarP(&despath, "despath", "d", "", "the image for push")
}
