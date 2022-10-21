package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/snyk/cli/cliv2/internal/cliv2"
	"github.com/snyk/cli/cliv2/internal/constants"
	"github.com/snyk/cli/cliv2/internal/proxy"
	"github.com/snyk/cli/cliv2/internal/utils"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/go-httpauth/pkg/httpauth"
	"github.com/spf13/cobra"
)

type EnvironmentVariables struct {
	CacheDirectory               string
	Insecure                     bool
	ProxyAuthenticationMechanism httpauth.AuthenticationMechanism
}

func getDebugLogger(args []string) *log.Logger {
	debugLogger := log.New(os.Stderr, "", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
	debug := utils.Contains(args, "--debug")

	if !debug {
		debug = utils.Contains(args, "-d")
	}

	if !debug {
		debugLogger.SetOutput(ioutil.Discard)
	}

	return debugLogger
}

func GetConfiguration(args []string) (EnvironmentVariables, []string) {
	envVariables := EnvironmentVariables{
		CacheDirectory:               os.Getenv("SNYK_CACHE_PATH"),
		ProxyAuthenticationMechanism: httpauth.AnyAuth,
		Insecure:                     false,
	}

	if utils.Contains(args, "--proxy-noauth") {
		envVariables.ProxyAuthenticationMechanism = httpauth.NoAuth
	}

	envVariables.Insecure = utils.Contains(args, "--insecure")

	// filter args not meant to be forwarded to CLIv1 or an Extensions
	elementsToFilter := []string{"--proxy-noauth"}
	filteredArgs := args
	for _, element := range elementsToFilter {
		filteredArgs = utils.RemoveSimilar(filteredArgs, element)
	}

	return envVariables, filteredArgs
}

func main() {
	config, args := GetConfiguration(os.Args[1:])
	errorCode := MainWithErrorCode(config, args)
	os.Exit(errorCode)
}

// main workflow
func runCommand(cmd *cobra.Command, args []string) error {
	fmt.Println("runCommand()", cmd)
	return nil
}

func MainWithErrorCode(envVariables EnvironmentVariables, args []string) int {
	var err error

	rootCommand := cobra.Command{
		Use: "snyk",
	}

	// create cobra, add global flagset and parse args
	// create engine
	// initialize the extensions -> they register themselves at the engine
	// engine.Init()
	// update cobra by adding flagset for each workflow
	// update configuration by adding flagset for each workflow
	// init associated packages like Analytics ...
	// use cobra to parse args -> invoke the appropriate command

	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)

	// init engine
	err = engine.Init()
	if err != nil {
		return constants.SNYK_EXIT_CODE_ERROR
	}

	workflowIdList := engine.GetWorkflows()
	fmt.Println("workflowIdList:", len(workflowIdList))
	for i := range workflowIdList {
		currentId := workflowIdList[i]
		currentCommandString := workflow.GetCommandFromWorkflowIdentifier(currentId)
		workflowEntry, _ := engine.GetWorkflow(currentId)
		workflowOptions := workflowEntry.GetConfigurationOptions()
		flagset := workflow.FlagsetFromConfigurationOptions(workflowOptions)

		cmd := cobra.Command{
			Use:  currentCommandString,
			Args: cobra.MaximumNArgs(1),
			RunE: runCommand,
		}

		if flagset != nil {
			cmd.Flags().AddFlagSet(flagset)
			config.AddFlagSet(flagset)
		}

		rootCommand.AddCommand(&cmd)

	}

	// init NetworkAccess
	networkAccess := engine.GetNetworkAccess()
	networkAccess.AddHeaderField("x-snyk-cli-version", cliv2.GetFullVersion())

	// init Analytics
	cliAnalytics := engine.GetAnalytics()
	cliAnalytics.SetVersion(cliv2.GetFullVersion())
	cliAnalytics.SetCmdArguments(args)
	if config.GetBool(configuration.ANALYTICS_DISABLED) == false {
		defer cliAnalytics.Send()
	}

	// run the extensible cli
	err = rootCommand.Execute()

	// ----------------------------------------------------------------
	// ----------------------------------------------------------------
	debugLogger := getDebugLogger(args)
	debugLogger.Println("debug: true")

	debugLogger.Println("cacheDirectory:", envVariables.CacheDirectory)
	debugLogger.Println("insecure:", envVariables.Insecure)

	if envVariables.CacheDirectory == "" {
		envVariables.CacheDirectory, err = utils.SnykCacheDir()
		if err != nil {
			fmt.Println("Failed to determine cache directory!")
			fmt.Println(err)
			return constants.SNYK_EXIT_CODE_ERROR
		}
	}

	// init cli object
	var cli *cliv2.CLI
	cli, err = cliv2.NewCLIv2(envVariables.CacheDirectory, debugLogger)
	if err != nil {
		cliAnalytics.AddError(err)
		return constants.SNYK_EXIT_CODE_ERROR
	}

	// init proxy object
	wrapperProxy, err := proxy.NewWrapperProxy(envVariables.Insecure, envVariables.CacheDirectory, cliv2.GetFullVersion(), debugLogger)
	defer wrapperProxy.Close()
	if err != nil {
		fmt.Println("Failed to create proxy")
		fmt.Println(err)
		cliAnalytics.AddError(err)
		return constants.SNYK_EXIT_CODE_ERROR
	}

	wrapperProxy.SetUpstreamProxyAuthentication(envVariables.ProxyAuthenticationMechanism)
	http.DefaultTransport = wrapperProxy.Transport()

	err = wrapperProxy.Start()
	if err != nil {
		fmt.Println("Failed to start the proxy")
		fmt.Println(err)
		cliAnalytics.AddError(err)
		return constants.SNYK_EXIT_CODE_ERROR
	}

	// run the cli
	proxyInfo := wrapperProxy.ProxyInfo()
	err = cli.Execute(proxyInfo, args)
	if err != nil {
		cliAnalytics.AddError(err)
	}

	exitCode := cli.DeriveExitCode(err)

	debugLogger.Printf("Exiting with %d\n", exitCode)

	return exitCode
}
