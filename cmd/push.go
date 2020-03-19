package cmd

import (
	"dp/registry"
	//"fmt"
	"github.com/spf13/cobra"
	"log"

)

var (
	//strict bool
	imgurl string
	user string
	passwd string
	imgpath string
)
var pushCmd = &cobra.Command{
	Use:     "push",
	Aliases: []string{"pu"},
	Short:   "push images",
	Long: `
version v0.1
push images without docker daemon.`,
	Example: `
# push image
dp push -u admin -p 123456 -i /root/redis.tar -l 172.18.0.52/alan/redis:latest
`,
	Run: func(cmd *cobra.Command, args []string) {
		//if len(args) == 0 {
		//	_ = cmd.Help()
		//	fmt.Println("please input args!!!")
		//	return
		//}
		dockrpusher := registry.Dockerpush{
			TagUrl:    imgurl,
			ImagePath: imgpath,
			User:  user,
			PassWd:    passwd,
		}
		dockrpusher.Pusher()
		log.Printf("Successfully push image %s", imgurl)

	},
}

func init() {
	rootCmd.AddCommand(pushCmd)
	//cpCmd.Flags().BoolVarP(&strict, "strict-mode", "s", false,
	//	"The image name of the push is strictly checked. If it is wrong, it will not be pushed.")
	pushCmd.Flags().StringVarP(&imgpath, "imgpath", "i", "", "image file path")
	pushCmd.Flags().StringVarP(&user, "user", "u", "admin", "the login name with harbor")
	pushCmd.Flags().StringVarP(&passwd, "password", "p", "", "the password with harbor")
	pushCmd.Flags().StringVarP(&imgurl, "imgurl", "l", "", "the image url")
}


