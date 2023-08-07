switch(code)
{
	case SHF_WRITE:
		printf("%-18s","SHF_WRITE");
		break;
	case SHF_ALLOC:
		printf("%-18s","SHF_ALLOC");
		break;
	case SHF_EXECINSTR:
		printf("%-18s","SHF_EXECINSTR");
		break;
	case SHF_MERGE:
		printf("%-18s","SHF_MERGE");
		break;
	case SHF_STRINGS:
		printf("%-18s","SHF_STRINGS");
		break;
	case SHF_INFO_LINK:
		printf("%-18s","SHF_INFO_LINK");
		break;
	case SHF_LINK_ORDER:
		printf("%-18s","SHF_LINK_ORDER");
		break;
	case SHF_GROUP:
		printf("%-18s","SHF_GROUP");
		break;
	case SHF_TLS:
		printf("%-18s","SHF_TLS");
		break;
	case SHF_COMPRESSED:
		printf("%-18s","SHF_COMPRESSED");
		break;
	case SHF_MASKOS:
		printf("%-18s","SHF_MASKOS");
		break;
	case SHF_MASKPROC:
		printf("%-18s","SHF_MASKPROC");
		break;
	default: 
		printf("Unknown\n");
		break;
}
