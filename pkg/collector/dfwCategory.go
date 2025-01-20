package collector

type DfwCategory int

const (
	EthernetCategory DfwCategory = iota
	EmergencyCategory
	InfrastructureCategory
	EnvCategory
	AppCategoty
	EmptyCategory
)

const (
	EthernetStr       = "Ethernet"
	EmergencyStr      = "Emergency"
	InfrastructureStr = "Infrastructure"
	EnvironmentStr    = "Environment"
	ApplicationStr    = "Application"
	EmptyStr          = "<Empty>"
)

/*func dfwCategoryFromString(s string) DfwCategory {
	switch s {
	case EthernetStr:
		return EthernetCategory
	case EmergencyStr:
		return EmergencyCategory
	case InfrastructureStr:
		return InfrastructureCategory
	case EnvironmentStr:
		return EnvCategory
	case ApplicationStr:
		return AppCategoty
	case EmptyStr:
		return EmptyCategory
	default:
		return EmptyCategory
	}
}*/

func (d DfwCategory) String() string {
	switch d {
	case EthernetCategory:
		return EthernetStr
	case EmergencyCategory:
		return EmergencyStr
	case InfrastructureCategory:
		return InfrastructureStr
	case EnvCategory:
		return EnvironmentStr
	case AppCategoty:
		return ApplicationStr
	case EmptyCategory:
		return EmptyStr
	default:
		return ""
	}
}

var CategoriesList = []DfwCategory{
	EthernetCategory, EmergencyCategory, InfrastructureCategory, EnvCategory, AppCategoty, EmptyCategory,
}
