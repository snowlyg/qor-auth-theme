package qor_auth_theme

import (
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/fatih/color"
	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/claims"
	"github.com/qor/auth/providers/password"
	"github.com/qor/i18n"
	"github.com/qor/i18n/backends/yaml"
	"github.com/qor/qor"
	"github.com/qor/qor/utils"
	"github.com/qor/render"
	registerviews "github.com/snowlyg/qor-registerviews"
)

// ErrPasswordConfirmationNotMatch password confirmation not match error
var ErrPasswordConfirmationNotMatch = errors.New("两次密码输入不一致")
var DefaultAuthorizeHandler = func(context *auth.Context) (*claims.Claims, error) {
	var (
		authInfo    auth_identity.AuthIdentity
		req         = context.Request
		tx          = context.Auth.GetDB(req)
		provider, _ = context.Provider.(*password.Provider)
	)

	_ = req.ParseForm()
	authInfo.Provider = provider.GetName()
	authInfo.UID = strings.TrimSpace(req.Form.Get("login"))

	if tx.Model(context.Auth.AuthIdentityModel).Where(authInfo).Scan(&authInfo).RecordNotFound() {
		return nil, errors.New("请输入正确账号")
	}

	if provider.Config.Confirmable && authInfo.ConfirmedAt == nil {
		currentUser, _ := context.Auth.UserStorer.Get(authInfo.ToClaims(), context)
		_ = provider.Config.ConfirmMailer(authInfo.UID, context, authInfo.ToClaims(), currentUser)

		return nil, errors.New("请确认你的账号，再继续")
	}

	if err := provider.Encryptor.Compare(authInfo.EncryptedPassword, strings.TrimSpace(req.Form.Get("password"))); err == nil {
		return authInfo.ToClaims(), err
	}

	return nil, errors.New("请输入正确密码")
}

// New initialize clean theme
func New(config *auth.Config) *auth.Auth {
	if config == nil {
		config = &auth.Config{}
	}
	config.URLPrefix = "admin"

	if config.DB == nil {
		fmt.Print("请为认证主题配置 *gorm.DB")
	}

	if config.Render == nil {
		yamlBackend := yaml.New()
		I18n := i18n.New(yamlBackend)

		filePath := registerviews.DetectViewsDir("github.com/snowlyg", "qor-auth-theme", "locales")
		if content, err := ioutil.ReadFile(filePath); err == nil {
			translations, _ := yamlBackend.LoadYAMLContent(content)
			for _, translation := range translations {
				_ = I18n.AddTranslation(translation)
			}
		}

		config.Render = render.New(&render.Config{
			FuncMapMaker: func(render *render.Render, req *http.Request, w http.ResponseWriter) template.FuncMap {
				return template.FuncMap{
					"t": func(key string, args ...interface{}) template.HTML {
						return I18n.T(utils.GetLocale(&qor.Context{Request: req}), key, args...)
					},
				}
			},
		})
	}

	if config.Render == nil {
		color.Red(fmt.Sprintf("render is %v\n", config.Render))
	}

	// 模版加载是前面覆盖后面
	registerPath(config, "github.com/snowlyg", "qor-auth-theme", "")

	// 支持 go mod 模式
	subpaths := []string{
		"/providers/password", "/providers/facebook", "/providers/twitter", "/providers/github", "",
	}
	pkgorg := "github.com/qor"
	pkgname := "auth"
	for _, subpaths := range subpaths {
		registerPath(config, pkgorg, pkgname, subpaths)
	}

	Auth := auth.New(config)

	Auth.RegisterProvider(password.New(&password.Config{
		Confirmable: true,
		RegisterHandler: func(context *auth.Context) (*claims.Claims, error) {
			_ = context.Request.ParseForm()

			if context.Request.Form.Get("confirm_password") != context.Request.Form.Get("password") {
				return nil, ErrPasswordConfirmationNotMatch
			}

			return password.DefaultRegisterHandler(context)
		},
		AuthorizeHandler: DefaultAuthorizeHandler,
	}))

	if Auth.Config.DB != nil {
		// Migrate Auth Identity model
		Auth.Config.DB.AutoMigrate(Auth.Config.AuthIdentityModel)
	}
	return Auth
}

// registerPath 注册视图
func registerPath(config *auth.Config, pkgorg, pkgname, subpaths string) {
	if err := config.Render.AssetFileSystem.RegisterPath(registerviews.DetectViewsDir(pkgorg, pkgname, subpaths)); err != nil {
		color.Red(fmt.Sprintf(" Auth.Render.AssetFileSystem.RegisterPath %v\n", err))
	}
}
