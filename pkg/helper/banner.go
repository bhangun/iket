package helper

import "fmt"

func PrintBanner(version string) {
	PrintBannerWithEdition(version, "")
}

func PrintBannerWithEdition(version, edition string) {
	blue := "\033[34m"
	red := "\033[31m"
	yellow := "\033[33m"
	reset := "\033[0m"
	fmt.Print(blue + `
 _ _                 
(_) |            _   
 _| |  _ _____ _| |_ 
| | |_/ ) ___ (_   _)
| |  _ (| ____| | |_ 
|_|_| \_)_____)  \__)` + red + " G a t e w a y \n\n" + reset)
	fmt.Printf(yellow+"Version: %s\n"+reset, version)
	if edition != "" {
		fmt.Printf(yellow+"Edition: %s\n"+reset, edition)
	}
	fmt.Println()
}
