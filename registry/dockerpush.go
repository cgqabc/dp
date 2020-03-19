package registry

import (
	"compress/gzip"
	"crypto/tls"
	//"github.com/prometheus/common/log"
    "log"
	//"archive/tar"
	"fmt"
	"io/ioutil"

	//"crypto/x509"
	"encoding/json"
	//"io/ioutil"
	"net/http"
	"os"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	//ts "github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	//"github.com/sirupsen/logrus"
)

//var tagUrl=flag.String("tagUrl", "", "上传的镜像地址")
//var	imagePath=flag.String("imagePath", "", "镜像文件路径")
//var	userName=flag.String("userName", "", "用户名")
//var	passWd=flag.String("passWd", "", "密码")

type Dockerpush struct {
	TagUrl    string
	ImagePath string
	User  string
	PassWd    string
}

//func main() {
//	Pusher()
//}


func (d *Dockerpush) Pusher() {
	//flag.Parse()
	// 设置日志为控制台输出
	//var log = logrus.New()
	//log.Out = os.Stdout
	//log.SetLevel(logrus.DebugLevel)
	//imgfile := "redis.tar"
	imgfile := d.ImagePath
	// 新增gzip解密判断
	unzipFile,err0 := ParseGzip(imgfile)
	if err0 == nil {
		imgfile = imgfile + ".tar"
		err0 = ioutil.WriteFile(imgfile, unzipFile, 0666)
		if err0 != nil {
			log.Printf("error info: %s",err0)
		}else{
			log.Printf("%s done unzip!",imgfile)
		}
	}


	var img v1.Image
	img, err := tarball.ImageFromPath(imgfile, nil)
	if err != nil {
		log.Printf("error info: %s",err)
		return
	}
	m, err := img.Digest()
	if err != nil {
		log.Printf("error info: %s",err)
		return
	}

	s, _ := img.Size()
	log.Printf("debianc.tar size:%d Digest:%s", s, m.String())

	//以下为ca证书校验过程
	// Read in the cert file
	//localCertFile := "ca.crt"
	//certs, err := ioutil.ReadFile(localCertFile)
	//if err != nil {
	//        logrus.Errorf("Failed to append %q to RootCAs: %v", localCertFile, err)
	//        return
	//}
	//// 自行新增定义
	//rootCAs := x509.NewCertPool()
	//// Append our cert to the system pool
	//if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
	//        logrus.Infof("No certs appended, using system certs only")
	//        return
	//}

	// Trust the augmented cert pool in our client
	//tlsConfig := &tls.Config{
	//        InsecureSkipVerify: false,
	//        RootCAs:            rootCAs,
	//}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, //忽略ca证书校验
		//RootCAs:            rootCAs,
	}

	transport := http.Transport{
		TLSClientConfig: tlsConfig,
	}

	//basicauth := NewBasicAuth("admin", "123456")    // registry user and password
	basicauth := NewBasicAuth(d.User, d.PassWd) // registry user and password
	//Push(img, "172.18.0.52/alan/redis:latest",
	errp := Push(img, d.TagUrl,
		WithInsecure(true),
		WithStrictValidation(true),
		//WithAuthFromDocker(),
		WithAuth(basicauth),
		WithTransport(&transport))
	//fmt.Printf("image: %s pushed done!!!", d.TagUrl)
	if errp != nil{
		log.Printf("push image faild ,error: %s",errp)
	}else{
		log.Printf("Successfully push image %s", d.TagUrl)
	}
}

//////////////////////////////////////////////////
// TROption is a functional option for crane.
type TROption func(*TROptions)

// WithAuth is a functional option for overriding the default authenticator
// for remote operations.
//
// The default authenticator is authn.Anonymous.
func WithAuth(auth authn.Authenticator) TROption {
	return func(o *TROptions) {
		o.remote = append(o.remote, remote.WithAuth(auth))
	}
}

func WithAuthFromDocker() TROption {
	return func(o *TROptions) {
		o.remote = append(o.remote, remote.WithAuthFromKeychain(DefaultKeychain))
	}
}

// WithTransport is a functional option for overriding the default transport
// for remote operations.
func WithTransport(t http.RoundTripper) TROption {
	return func(o *TROptions) {
		o.remote = append(o.remote, remote.WithTransport(t))
	}
}

// WithInsecure is an Option that allows image references to be fetched without TLS.
func WithInsecure(fg bool) TROption {
	return func(o *TROptions) {
		if fg {
			o.name = append(o.name, name.Insecure)
		}
	}
}

////// WithStrictValidation
//// if true
// StrictValidation is an Option that requires image references to be fully
// specified; i.e. no defaulting for registry (dockerhub), repo (library),
// or tag (latest).
//// if  false
// WeakValidation is an Option that sets defaults when parsing names, see
// StrictValidation.
func WithStrictValidation(fg bool) TROption {
	return func(o *TROptions) {
		if fg {
			o.name = append(o.name, name.StrictValidation)
		} else {
			o.name = append(o.name, name.WeakValidation)
		}
	}
}

type TROptions struct {
	name   []name.Option
	remote []remote.Option
}

func makeTROptions(opts ...TROption) TROptions {
	opt := TROptions{}

	for _, o := range opts {
		o(&opt)
	}

	return opt
}

///////////////////////////////////////////////////////////
// Push pushes the v1.Image img to a registry as dst.
func Push(img v1.Image, dst string, opt ...TROption) error {
	o := makeTROptions(opt...)
	tag, err := name.NewTag(dst, o.name...)
	if err != nil {
		log.Printf("parsing tag %q: %v", dst, err)
		return err
	}
	return remote.Write(tag, img, o.remote...)
}

////////////////////////////////////////////////////////////////////////
type defaultKeychain struct{}

var DefaultKeychain authn.Keychain = &defaultKeychain{}

// Resolve implements Keychain.
func (dk *defaultKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	cf, err := config.Load(os.Getenv("DOCKER_CONFIG"))
	if err != nil {
		return nil, err

	}

	// See:
	// https://github.com/google/ko/issues/90
	// https://github.com/moby/moby/blob/fc01c2b481097a6057bec3cd1ab2d7b4488c50c4/registry/config.go#L397-L404
	key := target.RegistryStr()

	cfg, err := cf.GetAuthConfig(key)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(cfg)
	if err == nil {
		log.Printf("defaultKeychain.Resolve(%q) = %s", key, string(b))
	}

	empty := types.AuthConfig{}
	if cfg == empty {
		return authn.Anonymous, nil

	}
	return authn.FromConfig(authn.AuthConfig{
		Username:      cfg.Username,
		Password:      cfg.Password,
		Auth:          cfg.Auth,
		IdentityToken: cfg.IdentityToken,
		RegistryToken: cfg.RegistryToken,
	}), nil
}

func NewBearerAuth(token string) authn.Authenticator {
	return &authn.Bearer{
		Token: token,
	}
}

func NewBasicAuth(u, p string) authn.Authenticator {
	return &authn.Basic{
		Username: u,
		Password: p,
	}
}


//解压 tar.gz
func ParseGzip(tarFile string) ([]byte, error) {
	srcFile, err := os.Open(tarFile)
	if err != nil {
		return nil,err
	}
	defer srcFile.Close()
	r, err := gzip.NewReader(srcFile)
	if err != nil {
		fmt.Printf("[ParseGzip] NewReader error: %v, maybe data is ungzip", err)
		return nil, err
	} else {
		defer r.Close()
		undatas, err := ioutil.ReadAll(r)
		if err != nil {
			fmt.Printf("[ParseGzip]  ioutil.ReadAll error: %v", err)
			return nil, err
		}
		return undatas, nil
	}
}