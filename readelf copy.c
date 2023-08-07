#include <stdio.h>
#include <elf.h>
#include <assert.h>
#include <string.h>

#define maxKilo 4096
#define maxLength maxKilo * 1024

#define EI_NIDENT (16)

#define SYS_32_BIT 0
#define SYS_64_BIT 1

#define numReadelfFlag 3

#define RESET "\033[0m" /* ANSI Command */						  // RESET
#define BOLD "\033[0m\033[1m"									  /* BOLD */
// #define KIRAKIRA "\033[5m" /* Flash */					  // KIRAKIRA
#define KIRADAME "\033[25m" /* Flash */					  // KIRADAME
#define KIRAKIRA KIRADAME
#define BLACK "\033[0m\033[30m"									  /* Black */
#define RED "\033[0m\033[31m"									  /* Red */
#define GREEN "\033[0m\033[32m"									  /* Green */
#define YELLOW "\033[0m\033[33m"								  /* Yellow */
#define BLUE "\033[0m\033[34m"									  /* Blue */
#define CYAN "\033[0m\033[36m"									  /* Cyan */
#define WHITE "\033[0m\033[37m"									  /* White */
#define WHITEBACK "\033[0m\033[107m" /* BrightWhite Background */ // Bright White
#define ORANGE "\033[0m\033[38;5;202m"
#define PURPLE "\033[0m\033[38;5;126m"
#define GREY250 "\033[0m\033[1m\033[38;5;250m"
FILE *elfFile;

char buffer[maxLength];

typedef enum
{
	ELF_32_BIT = 1,
	ELF_64_BIT = 2
} ELF_CLASS;

typedef enum
{
	READELF_HEADER = 0,
	READELF_SECTION = 1,
	READELF_SYMBOL = 2
} READELF_FLAG;

typedef enum
{
	ERR_GOOD = 0,
	ERR_LOAD_FAIL = 1,
	ERR_NOT_EXSIT = 2,
	ERR_UNKNOWN = 3
} STATE_CODE;

STATE_CODE flag;

READELF_FLAG readelf_flags[numReadelfFlag];

STATE_CODE fileOpen(char *dir);

ELF_CLASS getClass32(Elf32_Ehdr *header);
ELF_CLASS getClass64(Elf64_Ehdr *header);

#define getClass(header) _Generic( \
	header,                        \
	Elf32_Ehdr *                   \
	: getClass32,                  \
	  Elf64_Ehdr *                 \
	: getClass64)(header)

STATE_CODE getDataEncoding(unsigned char code);

STATE_CODE getVersion(unsigned char code);

STATE_CODE getSystemName(unsigned char code);

STATE_CODE getABIVersion(unsigned char code);

STATE_CODE getType(uint16_t code);

STATE_CODE getMachine(uint16_t code);

STATE_CODE getVersionHex(uint32_t code);

STATE_CODE getEntry32(uint32_t addr);
STATE_CODE getEntry64(uint64_t addr);

#define getEntry(addr) _Generic( \
	addr,                        \
	uint32_t                     \
	: getEntry32,                \
	  uint64_t                   \
	: getEntry64)(addr)

STATE_CODE getPhoff32(uint32_t addr);
STATE_CODE getPhoff64(uint64_t addr);

#define getPhoff(addr) _Generic( \
	addr,                        \
	uint32_t                     \
	: getPhoff32,                \
	  uint64_t                   \
	: getPhoff64)(addr)

STATE_CODE getShoff32(uint32_t addr);
STATE_CODE getShoff64(uint64_t addr);

#define getShoff(addr) _Generic( \
	addr,                        \
	uint32_t                     \
	: getShoff32,                \
	  uint64_t                   \
	: getShoff64)(addr)

STATE_CODE getFlags(uint32_t addr);

STATE_CODE getEhsize(uint16_t addr);

STATE_CODE getPhentsize(uint16_t addr);

STATE_CODE getPhnum(uint16_t addr);

STATE_CODE getShentsize(uint16_t addr);

STATE_CODE getShnum(uint16_t addr);

STATE_CODE getShstrndx(uint16_t addr);

STATE_CODE getSectionFlag32(uint32_t addr);
STATE_CODE getSectionFlag64(uint64_t addr);

STATE_CODE check_readelf_flags(int num_flags, char *argv[]);

STATE_CODE getShtype(uint32_t code);

STATE_CODE getStentrytype(unsigned char code);

STATE_CODE getStentrybind(unsigned char code);
STATE_CODE getStentryvis(unsigned char code);

STATE_CODE getStentryNdx(uint16_t code);

#define getSectionFlag(addr) _Generic( \
	addr,                              \
	uint32_t                           \
	: getSectionFlag32,                \
	  uint64_t                         \
	: getSectionFlag64)(addr)

STATE_CODE read32Header(Elf32_Ehdr *header32);
STATE_CODE read64Header(Elf64_Ehdr *header64);

#define readHeader(header) _Generic( \
	header,                          \
	Elf32_Ehdr *                     \
	: read32Header,                  \
	  Elf64_Ehdr *                   \
	: read64Header)(header)

STATE_CODE read32Section(Elf32_Ehdr *header32);
STATE_CODE read64Section(Elf64_Ehdr *header64);

#define readSection(header) _Generic( \
	header,                           \
	Elf32_Ehdr *                      \
	: read32Section,                  \
	  Elf64_Ehdr *                    \
	: read64Section)(header)

STATE_CODE read32Symtab(Elf32_Ehdr *header32);
STATE_CODE read64Symtab(Elf64_Ehdr *header64);

#define readSymtab(header) _Generic( \
	header,                          \
	Elf32_Ehdr *                     \
	: read32Symtab,                  \
	  Elf64_Ehdr *                   \
	: read64Symtab)(header)

STATE_CODE fileHeader(char *buffer);

void printUsage();

char *rainbow(int index);

int main(int argc, char *argv[])
{
	if (argc <= 2 || (flag = fileOpen(argv[argc - 1])) == ERR_LOAD_FAIL || check_readelf_flags(argc - 2, argv) == ERR_NOT_EXSIT)
	{
		printUsage();
		return 1;
	}
	int fileLength;
	fileLength = fread(buffer, 1, maxLength, elfFile);
	buffer[fileLength] = '\0';

	flag = fileHeader(buffer);

	return 0;
}

STATE_CODE check_readelf_flags(int num_flags, char *argv[])
{
	if (num_flags == 0)
		return ERR_GOOD;
	char elf_header_sign[] = "-h", elf_header_sign_alias1[] = "--file-header";
	char elf_section_sign[] = "-S", elf_section_sign_alias1[] = "--section-headers", elf_section_sign_alias2[] = "--sections";
	char elf_syms_sign[] = "-s", elf_syms_sign_alias1[] = "--syms", elf_syms_sign_alias2[] = "--symbols";
	if (strcmp(argv[num_flags], elf_header_sign) == 0 || (strcmp(argv[num_flags], elf_header_sign_alias1)) == 0)
	{
		readelf_flags[READELF_HEADER] = 1;
	}

	else if (strcmp(argv[num_flags], elf_section_sign) == 0 || (strcmp(argv[num_flags], elf_section_sign_alias1)) == 0 || (strcmp(argv[num_flags], elf_section_sign_alias2)) == 0)
	{
		readelf_flags[READELF_SECTION] = 1;
	}

	else if (strcmp(argv[num_flags], elf_syms_sign) == 0 || (strcmp(argv[num_flags], elf_syms_sign_alias1)) == 0 || (strcmp(argv[num_flags], elf_syms_sign_alias2)) == 0)
	{
		readelf_flags[READELF_SYMBOL] = 1;
	}

	else
		return ERR_NOT_EXSIT;

	return check_readelf_flags((num_flags - 1), argv);
}

void printUsage()
{
	printf("%s\n", "Usage: ./readelf <option(s)> elf-file");
	printf(" %s\n", "Display information about the contents of ELF format files");
	printf(" %s\n", "Options are:");
	printf("  %-3s%-20s%s\n", "-a", "--all", "Equivalent to: -h -S -s");
	printf("  %-3s%-20s%s\n", "-h", "--file-header", "Display the ELF file header");
	printf("  %-3s%-20s%s\n", "-S", "--section-headers", "Display the sections\' header");
	printf("  %-3s%-20s%s\n", "  ", "--sections", "An alias for --section-headers");
	printf("  %-3s%-20s%s\n", "-s", "--syms", "Display the symbol table");
	printf("  %-3s%-20s%s\n", "  ", "--symbols", "An alias for --syms");
}

STATE_CODE
fileOpen(char *dir)
{
	elfFile = fopen(dir, "rb+");
	if (elfFile == NULL)
		return ERR_LOAD_FAIL;
	return ERR_GOOD;
}

ELF_CLASS
getClass32(Elf32_Ehdr *header)
{
	if (header->e_ident[EI_CLASS] == ELFCLASS32)
		return ELF_32_BIT;
	else
		return ELF_64_BIT;
}

ELF_CLASS
getClass64(Elf64_Ehdr *header)
{
	if (header->e_ident[EI_CLASS] == ELFCLASS32)
		return ELF_32_BIT;
	else
		return ELF_64_BIT;
}

STATE_CODE
getDataEncoding(unsigned char code)
{
	printf("  %s%-35s", GREEN, "Data:");
	switch (code)
	{
	case ELFDATANONE:
		printf("Invalid data encoding\n");
		break;

	case ELFDATA2LSB:
		printf("2\'s complement, little endian\n");
		break;
	case ELFDATA2MSB:
		printf("2's complement, big endian\n");
		break;
	}
	return ERR_GOOD;
}

STATE_CODE
getVersion(unsigned char code)
{
	printf("  %s%-35s", CYAN, "Version:");
	switch (code)
	{
	case EV_NONE:
		printf("Invalid ELF Version\n");
		break;

	case EV_CURRENT:
		printf("1 (current)\n");
		break;
	}
	return ERR_GOOD;
}

STATE_CODE
getSystemName(unsigned char code)
{
	printf("  %s%-35s", BLUE, "OS/ABI:");
	switch (code)
	{
	case ELFOSABI_NONE:
		printf("UNIX - System V\n");
		break;

	case ELFOSABI_HPUX:
		printf("HP-UX\n");
		break;
	case ELFOSABI_NETBSD:
		printf("NetBSD\n");
		break;
	case ELFOSABI_LINUX:
		printf("Linux\n");
		break;
	case ELFOSABI_SOLARIS:
		printf("Sun Solaris\n");
		break;
	case ELFOSABI_AIX:
		printf("IBM AIX\n");
		break;
	case ELFOSABI_IRIX:
		printf("SGI Irix\n");
		break;
	case ELFOSABI_FREEBSD:
		printf("FreeBSD\n");
		break;
	case ELFOSABI_TRU64:
		printf("Compaq TRU64 UNIX\n");
		break;
	case ELFOSABI_MODESTO:
		printf("Novell Modesto\n");
		break;
	case ELFOSABI_OPENBSD:
		printf("OpenBSD\n");
		break;
	case ELFOSABI_ARM_AEABI:
		printf("ARM EABI\n");
		break;
	case ELFOSABI_ARM:
		printf("ARM\n");
		break;
	case ELFOSABI_STANDALONE:
		printf("Standalone (embedded) application\n");
		break;
	default:
		printf("Unknown\n");
		break;
	}
	return ERR_GOOD;
}

STATE_CODE
getABIVersion(unsigned char code)
{
	printf("  %s%-35s", PURPLE, "ABI Version:");
	switch (code)
	{
	default:
		printf("0\n");
		break;
	}
	return ERR_GOOD;
}

STATE_CODE
getType(uint16_t code)
{
	printf("  %s%-35s", RED, "Type:");
	switch (code)
	{
	case ET_NONE:
		printf("No file type\n");
		break;
	case ET_REL:
		printf("REL (Relocatable file)\n");
		break;
	case ET_EXEC:
		printf("EXEC (Executable file)\n");
		break;
	case ET_DYN:
		printf("DYN (Shared object file)\n");
		break;
	case ET_CORE:
		printf("CORE (Core file)\n");
		break;
	case ET_NUM:
		printf("NUM (Number of defined types)\n");
		break;
	case ET_LOOS:
		printf("LOOS (OS-specific range start)\n");
		break;
	case ET_HIOS:
		printf("HIOS (OS-specific range end)\n");
		break;
	case ET_LOPROC:
		printf("LOPROC (Processor-specific range start)\n");
		break;
	case ET_HIPROC:
		printf("HIPROC (Processor-specific range end)\n");
		break;
	default:
		printf("Unknown\n");
		break;
	}
	return ERR_GOOD;
}

STATE_CODE
getMachine(uint16_t code)
{
	printf("  %s%-35s", ORANGE, "Machine:");
	switch (code)
	{
	case EM_NONE:
		printf("No machine\n");
		break;
	case EM_M32:
		printf("AT&T WE 32100\n");
		break;
	case EM_SPARC:
		printf("SUN SPARC\n");
		break;
	case EM_386:
		printf("Intel 80386\n");
		break;
	case EM_68K:
		printf("Motorola m68k family\n");
		break;
	case EM_88K:
		printf("Motorola m88k family\n");
		break;
	case EM_IAMCU:
		printf("Intel MCU\n");
		break;
	case EM_860:
		printf("Intel 80860\n");
		break;
	case EM_MIPS:
		printf("MIPS R3000 big-endian\n");
		break;
	case EM_S370:
		printf("IBM System/370\n");
		break;
	case EM_MIPS_RS3_LE:
		printf("MIPS R3000 little-endian\n");
		break;
	case EM_PARISC:
		printf("HPPA\n");
		break;
	case EM_VPP500:
		printf("Fujitsu VPP500\n");
		break;
	case EM_SPARC32PLUS:
		printf("Sun's v8plus\n");
		break;
	case EM_960:
		printf("Intel 80960\n");
		break;
	case EM_PPC:
		printf("PowerPC\n");
		break;
	case EM_PPC64:
		printf("PowerPC 64-bit\n");
		break;
	case EM_S390:
		printf("IBM S390\n");
		break;
	case EM_SPU:
		printf("IBM SPU/SPC\n");
		break;
	case EM_V800:
		printf("NEC V800 series\n");
		break;
	case EM_FR20:
		printf("Fujitsu FR20\n");
		break;
	case EM_RH32:
		printf("TRW RH-32\n");
		break;
	case EM_RCE:
		printf("Motorola RCE\n");
		break;
	case EM_ARM:
		printf("ARM\n");
		break;
	case EM_FAKE_ALPHA:
		printf("Digital Alpha\n");
		break;
	case EM_SH:
		printf("Hitachi SH\n");
		break;
	case EM_SPARCV9:
		printf("SPARC v9 64-bit\n");
		break;
	case EM_TRICORE:
		printf("Siemens Tricore\n");
		break;
	case EM_ARC:
		printf("Argonaut RISC Core\n");
		break;
	case EM_H8_300:
		printf("Hitachi H8/300\n");
		break;
	case EM_H8_300H:
		printf("Hitachi H8/300H\n");
		break;
	case EM_H8S:
		printf("Hitachi H8S\n");
		break;
	case EM_H8_500:
		printf("Hitachi H8/500\n");
		break;
	case EM_IA_64:
		printf("Intel Merced\n");
		break;
	case EM_MIPS_X:
		printf("Stanford MIPS-X\n");
		break;
	case EM_COLDFIRE:
		printf("Motorola Coldfire\n");
		break;
	case EM_68HC12:
		printf("Motorola M68HC12\n");
		break;
	case EM_MMA:
		printf("Fujitsu MMA Multimedia Accelerator\n");
		break;
	case EM_PCP:
		printf("Siemens PCP\n");
		break;
	case EM_NCPU:
		printf("Sony nCPU embeeded RISC\n");
		break;
	case EM_NDR1:
		printf("Denso NDR1 microprocessor\n");
		break;
	case EM_STARCORE:
		printf("Motorola Start*Core processor\n");
		break;
	case EM_ME16:
		printf("Toyota ME16 processor\n");
		break;
	case EM_ST100:
		printf("STMicroelectronic ST100 processor\n");
		break;
	case EM_TINYJ:
		printf("Advanced Logic Corp. Tinyj emb.fam\n");
		break;
	case EM_X86_64:
		printf("AMD x86-64 architecture\n");
		break;
	case EM_PDSP:
		printf("Sony DSP Processor\n");
		break;
	case EM_PDP10:
		printf("Digital PDP-10\n");
		break;
	case EM_PDP11:
		printf("Digital PDP-11\n");
		break;
	case EM_FX66:
		printf("Siemens FX66 microcontroller\n");
		break;
	case EM_ST9PLUS:
		printf("STMicroelectronics ST9+ 8/16 mc\n");
		break;
	case EM_ST7:
		printf("STmicroelectronics ST7 8 bit mc\n");
		break;
	case EM_68HC16:
		printf("Motorola MC68HC16 microcontroller\n");
		break;
	case EM_68HC11:
		printf("Motorola MC68HC11 microcontroller\n");
		break;
	case EM_68HC08:
		printf("Motorola MC68HC08 microcontroller\n");
		break;
	case EM_68HC05:
		printf("Motorola MC68HC05 microcontroller\n");
		break;
	case EM_SVX:
		printf("Silicon Graphics SVx\n");
		break;
	case EM_ST19:
		printf("STMicroelectronics ST19 8 bit mc\n");
		break;
	case EM_VAX:
		printf("Digital VAX\n");
		break;
	case EM_CRIS:
		printf("Axis Communications 32-bit emb.proc\n");
		break;
	case EM_JAVELIN:
		printf("Infineon Technologies 32-bit emb.proc\n");
		break;
	case EM_FIREPATH:
		printf("Element 14 64-bit DSP Processor\n");
		break;
	case EM_ZSP:
		printf("LSI Logic 16-bit DSP Processor\n");
		break;
	case EM_MMIX:
		printf("Donald Knuth's educational 64-bit proc\n");
		break;
	case EM_HUANY:
		printf("Harvard University machine-independent object files\n");
		break;
	case EM_PRISM:
		printf("SiTera Prism\n");
		break;
	case EM_AVR:
		printf("Atmel AVR 8-bit microcontroller\n");
		break;
	case EM_FR30:
		printf("Fujitsu FR30\n");
		break;
	case EM_D10V:
		printf("Mitsubishi D10V\n");
		break;
	case EM_D30V:
		printf("Mitsubishi D30V\n");
		break;
	case EM_V850:
		printf("NEC v850\n");
		break;
	case EM_M32R:
		printf("Mitsubishi M32R\n");
		break;
	case EM_MN10300:
		printf("Matsushita MN10300\n");
		break;
	case EM_MN10200:
		printf("Matsushita MN10200\n");
		break;
	case EM_PJ:
		printf("picoJava\n");
		break;
	case EM_OPENRISC:
		printf("OpenRISC 32-bit embedded processor\n");
		break;
	case EM_ARC_COMPACT:
		printf("ARC International ARCompact\n");
		break;
	case EM_XTENSA:
		printf("Tensilica Xtensa Architecture\n");
		break;
	case EM_VIDEOCORE:
		printf("Alphamosaic VideoCore\n");
		break;
	case EM_TMM_GPP:
		printf("Thompson Multimedia General Purpose Proc\n");
		break;
	case EM_NS32K:
		printf("National Semi. 32000\n");
		break;
	case EM_TPC:
		printf("Tenor Network TPC\n");
		break;
	case EM_SNP1K:
		printf("Trebia SNP 1000\n");
		break;
	case EM_ST200:
		printf("STMicroelectronics ST200\n");
		break;
	case EM_IP2K:
		printf("Ubicom IP2xxx\n");
		break;
	case EM_MAX:
		printf("MAX processor\n");
		break;
	case EM_CR:
		printf("National Semi. CompactRISC\n");
		break;
	case EM_F2MC16:
		printf("Fujitsu F2MC16\n");
		break;
	case EM_MSP430:
		printf("Texas Instruments msp430\n");
		break;
	case EM_BLACKFIN:
		printf("Analog Devices Blackfin DSP\n");
		break;
	case EM_SE_C33:
		printf("Seiko Epson S1C33 family\n");
		break;
	case EM_SEP:
		printf("Sharp embedded microprocessor\n");
		break;
	case EM_ARCA:
		printf("Arca RISC\n");
		break;
	case EM_UNICORE:
		printf("PKU-Unity & MPRC Peking Uni. mc series\n");
		break;
	case EM_EXCESS:
		printf("eXcess configurable cpu\n");
		break;
	case EM_DXP:
		printf("Icera Semi. Deep Execution Processor\n");
		break;
	case EM_ALTERA_NIOS2:
		printf("Altera Nios II\n");
		break;
	case EM_CRX:
		printf("National Semi. CompactRISC CRX\n");
		break;
	case EM_XGATE:
		printf("Motorola XGATE\n");
		break;
	case EM_C166:
		printf("Infineon C16x/XC16x\n");
		break;
	case EM_M16C:
		printf("Renesas M16C\n");
		break;
	case EM_DSPIC30F:
		printf("Microchip Technology dsPIC30F\n");
		break;
	case EM_CE:
		printf("Freescale Communication Engine RISC\n");
		break;
	case EM_M32C:
		printf("Renesas M32C\n");
		break;
	case EM_TSK3000:
		printf("Altium TSK3000\n");
		break;
	case EM_RS08:
		printf("Freescale RS08\n");
		break;
	case EM_SHARC:
		printf("Analog Devices SHARC family\n");
		break;
	case EM_ECOG2:
		printf("Cyan Technology eCOG2\n");
		break;
	case EM_SCORE7:
		printf("Sunplus S+core7 RISC\n");
		break;
	case EM_DSP24:
		printf("New Japan Radio (NJR) 24-bit DSP\n");
		break;
	case EM_VIDEOCORE3:
		printf("Broadcom VideoCore III\n");
		break;
	case EM_LATTICEMICO32:
		printf("RISC for Lattice FPGA\n");
		break;
	case EM_SE_C17:
		printf("Seiko Epson C17\n");
		break;
	case EM_TI_C6000:
		printf("Texas Instruments TMS320C6000 DSP\n");
		break;
	case EM_TI_C2000:
		printf("Texas Instruments TMS320C2000 DSP\n");
		break;
	case EM_TI_C5500:
		printf("Texas Instruments TMS320C55x DSP\n");
		break;
	case EM_TI_ARP32:
		printf("Texas Instruments App. Specific RISC\n");
		break;
	case EM_TI_PRU:
		printf("Texas Instruments Prog. Realtime Unit\n");
		break;
	case EM_MMDSP_PLUS:
		printf("STMicroelectronics 64bit VLIW DSP\n");
		break;
	case EM_CYPRESS_M8C:
		printf("Cypress M8C\n");
		break;
	case EM_R32C:
		printf("Renesas R32C\n");
		break;
	case EM_TRIMEDIA:
		printf("NXP Semi. TriMedia\n");
		break;
	case EM_QDSP6:
		printf("QUALCOMM DSP6\n");
		break;
	case EM_8051:
		printf("Intel 8051 and variants\n");
		break;
	case EM_STXP7X:
		printf("STMicroelectronics STxP7x\n");
		break;
	case EM_NDS32:
		printf("Andes Tech. compact code emb. RISC\n");
		break;
	case EM_ECOG1X:
		printf("Cyan Technology eCOG1X\n");
		break;
	case EM_MAXQ30:
		printf("Dallas Semi. MAXQ30 mc\n");
		break;
	case EM_XIMO16:
		printf("New Japan Radio (NJR) 16-bit DSP\n");
		break;
	case EM_MANIK:
		printf("M2000 Reconfigurable RISC\n");
		break;
	case EM_CRAYNV2:
		printf("Cray NV2 vector architecture\n");
		break;
	case EM_RX:
		printf("Renesas RX\n");
		break;
	case EM_METAG:
		printf("Imagination Tech. META\n");
		break;
	case EM_MCST_ELBRUS:
		printf("MCST Elbrus\n");
		break;
	case EM_ECOG16:
		printf("Cyan Technology eCOG16\n");
		break;
	case EM_CR16:
		printf("National Semi. CompactRISC CR16\n");
		break;
	case EM_ETPU:
		printf("Freescale Extended Time Processing Unit\n");
		break;
	case EM_SLE9X:
		printf("Infineon Tech. SLE9X\n");
		break;
	case EM_L10M:
		printf("Intel L10M\n");
		break;
	case EM_K10M:
		printf("Intel K10M\n");
		break;
	case EM_AARCH64:
		printf("ARM AARCH64\n");
		break;
	case EM_AVR32:
		printf("Amtel 32-bit microprocessor\n");
		break;
	case EM_STM8:
		printf("STMicroelectronics STM8\n");
		break;
	case EM_TILE64:
		printf("Tileta TILE64\n");
		break;
	case EM_TILEPRO:
		printf("Tilera TILEPro\n");
		break;
	case EM_MICROBLAZE:
		printf("Xilinx MicroBlaze\n");
		break;
	case EM_CUDA:
		printf("NVIDIA CUDA\n");
		break;
	case EM_TILEGX:
		printf("Tilera TILE-Gx\n");
		break;
	case EM_CLOUDSHIELD:
		printf("CloudShield\n");
		break;
	case EM_COREA_1ST:
		printf("KIPO-KAIST Core-A 1st gen.\n");
		break;
	case EM_COREA_2ND:
		printf("KIPO-KAIST Core-A 2nd gen.\n");
		break;
	case EM_ARC_COMPACT2:
		printf("Synopsys ARCompact V2\n");
		break;
	case EM_OPEN8:
		printf("Open8 RISC\n");
		break;
	case EM_RL78:
		printf("Renesas RL78\n");
		break;
	case EM_VIDEOCORE5:
		printf("Broadcom VideoCore V\n");
		break;
	case EM_78KOR:
		printf("Renesas 78KOR\n");
		break;
	case EM_56800EX:
		printf("Freescale 56800EX DSC\n");
		break;
	case EM_BA1:
		printf("Beyond BA1\n");
		break;
	case EM_BA2:
		printf("Beyond BA2\n");
		break;
	case EM_XCORE:
		printf("XMOS xCORE\n");
		break;
	case EM_MCHP_PIC:
		printf("Microchip 8-bit PIC(r)\n");
		break;
	case EM_KM32:
		printf("KM211 KM32\n");
		break;
	case EM_KMX32:
		printf("KM211 KMX32\n");
		break;
	case EM_EMX16:
		printf("KM211 KMX16\n");
		break;
	case EM_EMX8:
		printf("KM211 KMX8\n");
		break;
	case EM_KVARC:
		printf("KM211 KVARC\n");
		break;
	case EM_CDP:
		printf("Paneve CDP\n");
		break;
	case EM_COGE:
		printf("Cognitive Smart Memory Processor\n");
		break;
	case EM_COOL:
		printf("Bluechip CoolEngine\n");
		break;
	case EM_NORC:
		printf("Nanoradio Optimized RISC\n");
		break;
	case EM_CSR_KALIMBA:
		printf("CSR Kalimba\n");
		break;
	case EM_Z80:
		printf("Zilog Z80\n");
		break;
	case EM_VISIUM:
		printf("Controls and Data Services VISIUMcore\n");
		break;
	case EM_FT32:
		printf("FTDI Chip FT32\n");
		break;
	case EM_MOXIE:
		printf("Moxie processor\n");
		break;
	case EM_AMDGPU:
		printf("AMD GPU\n");
		break;
	case EM_RISCV:
		printf("RISC-V\n");
		break;
	case EM_BPF:
		printf("Linux BPF -- in-kernel virtual machine\n");
		break;
	case EM_CSKY:
		printf("C-SKY\n");
		break;
	default:
		printf("Unknown\n");
		break;
	}
	return ERR_GOOD;
}
STATE_CODE getVersionHex(uint32_t code)
{
	printf("  %s%-35s", YELLOW, "Version:");
	switch (code)
	{
	case EV_NONE:
		printf("0x0\n");
		break;

	case EV_CURRENT:
		printf("0x1\n");
		break;
	}
	return ERR_GOOD;
}

STATE_CODE getEntry32(uint32_t addr)
{
	printf("  %s%-35s0x%x\n", GREEN, "Entry point address:", addr);
	return ERR_GOOD;
}

STATE_CODE getEntry64(uint64_t addr)
{
	printf("  %s%-35s0x%lx\n", GREEN, "Entry point address:", addr);
	return ERR_GOOD;
}

STATE_CODE getPhoff32(uint32_t addr)
{
	printf("  %s%-35s%u (bytes into file)\n", CYAN, "Start of program headers:", addr);
	return ERR_GOOD;
}

STATE_CODE getPhoff64(uint64_t addr)
{
	printf("  %s%-35s%lu (bytes into file)\n", CYAN, "Start of program headers:", addr);
	return ERR_GOOD;
}

STATE_CODE getShoff32(uint32_t addr)
{
	printf("  %s%-35s%u (bytes into file)\n", BLUE, "Start of section headers:", addr);
	return ERR_GOOD;
}

STATE_CODE getShoff64(uint64_t addr)
{
	printf("  %s%-35s%lu (bytes into file)\n", BLUE, "Start of section headers:", addr);
	return ERR_GOOD;
}

STATE_CODE getFlags(uint32_t addr)
{
	printf("  %s%-35s0x%u\n", PURPLE, "Flags:", addr);
	return ERR_GOOD;
}

STATE_CODE getEhsize(uint16_t addr)
{
	printf("  %s%-35s%hu (bytes)\n", RED, "Size of this header:", addr);
	return ERR_GOOD;
}
STATE_CODE getPhentsize(uint16_t addr)
{
	printf("  %s%-35s%hu (bytes)\n", ORANGE, "Size of program headers:", addr);
	return ERR_GOOD;
}

STATE_CODE getPhnum(uint16_t addr)
{
	printf("  %s%-35s%hu\n", YELLOW, "Number of program headers:", addr);
	return ERR_GOOD;
}

STATE_CODE getShentsize(uint16_t addr)
{
	printf("  %s%-35s%hu (bytes)\n", GREEN, "Size of section headers:", addr);
	return ERR_GOOD;
}

STATE_CODE getShnum(uint16_t addr)
{
	printf("  %s%-35s%hu\n", CYAN, "Number of section headers:", addr);
	return ERR_GOOD;
}

STATE_CODE getShstrndx(uint16_t addr)
{
	printf("  %s%-35s%hu\n", BLUE, "Section header string table index:", addr);
	return ERR_GOOD;
}

STATE_CODE getShtype(uint32_t code)
{
	switch (code)
	{
	case SHT_NULL:
		printf("%-17s", "NULL");
		break;
	case SHT_PROGBITS:
		printf("%-17s", "PROGBITS");
		break;
	case SHT_SYMTAB:
		printf("%-17s", "SYMTAB");
		break;
	case SHT_STRTAB:
		printf("%-17s", "STRTAB");
		break;
	case SHT_RELA:
		printf("%-17s", "RELA");
		break;
	case SHT_HASH:
		printf("%-17s", "HASH");
		break;
	case SHT_DYNAMIC:
		printf("%-17s", "DYNAMIC");
		break;
	case SHT_NOTE:
		printf("%-17s", "NOTE");
		break;
	case SHT_NOBITS:
		printf("%-17s", "NOBITS");
		break;
	case SHT_REL:
		printf("%-17s", "REL");
		break;
	case SHT_SHLIB:
		printf("%-17s", "SHLIB");
		break;
	case SHT_DYNSYM:
		printf("%-17s", "DYNSYM");
		break;
	case SHT_INIT_ARRAY:
		printf("%-17s", "INIT_ARRAY");
		break;
	case SHT_FINI_ARRAY:
		printf("%-17s", "FINI_ARRAY");
		break;
	case SHT_PREINIT_ARRAY:
		printf("%-17s", "PREINIT_ARRAY");
		break;
	case SHT_GROUP:
		printf("%-17s", "GROUP");
		break;
	case SHT_SYMTAB_SHNDX:
		printf("%-17s", "SYMTAB_SHNDX");
		break;
	case SHT_LOOS:
		printf("%-17s", "LOOS");
		break;
	case SHT_GNU_ATTRIBUTES:
		printf("%-17s", "GNU_ATTRIBUTES");
		break;
	case SHT_GNU_HASH:
		printf("%-17s", "GNU_HASH");
		break;
	case SHT_GNU_LIBLIST:
		printf("%-17s", "GNU_LIBLIST");
		break;
	case SHT_CHECKSUM:
		printf("%-17s", "CHECKSUM");
		break;
	case SHT_LOSUNW:
		printf("%-17s", "LOSUNW");
		break;
	case SHT_GNU_versym:
		printf("%-17s", "GNU_versym");
		break;
	case SHT_LOPROC:
		printf("%-17s", "LOPROC");
		break;
	case SHT_HIPROC:
		printf("%-17s", "HIPROC");
		break;
	case SHT_LOUSER:
		printf("%-17s", "LOUSER");
		break;
	default:
		printf("%-17s", "Unknown");
		break;
	}

	return ERR_GOOD;
}

STATE_CODE getSectionFlag32(uint32_t addr)
{
	char flags[1024] = "";
	if ((uint32_t)(addr & SHF_WRITE) == (uint32_t)SHF_WRITE)
	{
		char *p = "W";
		strcat(flags, p);
	}
	if ((uint32_t)(addr & SHF_ALLOC) == (uint32_t)SHF_ALLOC)
	{
		char *p = "A";
		strcat(flags, p);
	}
	if ((uint32_t)(addr & SHF_EXECINSTR) == (uint32_t)SHF_EXECINSTR)
	{
		char *p = "X";
		strcat(flags, p);
	}
	if ((uint32_t)(addr & SHF_MERGE) == (uint32_t)(SHF_MERGE))
	{
		char *p = "M";
		strcat(flags, p);
	}
	if ((uint32_t)(addr & SHF_STRINGS) == (uint32_t)SHF_STRINGS)
	{
		char *p = "S";
		strcat(flags, p);
	}
	if ((uint32_t)(addr & SHF_INFO_LINK) == (uint32_t)SHF_INFO_LINK)
	{
		char *p = "I";
		strcat(flags, p);
	}
	if ((uint32_t)(addr & SHF_LINK_ORDER) == (uint32_t)SHF_LINK_ORDER)
	{
		char *p = "L";
		strcat(flags, p);
	}
	if ((uint32_t)(addr & SHF_OS_NONCONFORMING) == (uint32_t)SHF_OS_NONCONFORMING)
	{
		char *p = "O";
		strcat(flags, p);
	}
	if ((uint32_t)(addr & SHF_GROUP) == (uint32_t)SHF_GROUP)
	{
		char *p = "G";
		strcat(flags, p);
	}
	if ((uint32_t)(addr & SHF_TLS) == (uint32_t)SHF_TLS)
	{
		char *p = "T";
		strcat(flags, p);
	}
	if ((uint32_t)(addr & SHF_COMPRESSED) == (uint32_t)SHF_COMPRESSED)
	{
		char *p = "C";
		strcat(flags, p);
	}
	/* Preserved x */

	if ((uint32_t)(addr & SHF_MASKOS) == (uint32_t)SHF_MASKOS)
	{
		char *p = "o";
		strcat(flags, p);
	}
	if ((uint32_t)(addr & SHF_EXCLUDE) == (uint32_t)SHF_EXCLUDE)
	{
		char *p = "E";
		strcat(flags, p);
	}
	/* Preserved l */

	if ((uint32_t)(addr & SHF_MASKPROC) == (uint32_t)SHF_MASKPROC)
	{
		char *p = "p";
		strcat(flags, p);
	}

	printf("%-5s  ", flags); // FLAG

	return ERR_GOOD;
}
STATE_CODE getSectionFlag64(uint64_t addr)
{
	char flags[1024] = "";
	if ((uint64_t)(addr & SHF_WRITE) == (uint64_t)SHF_WRITE)
	{
		char *p = "W";
		strcat(flags, p);
	}
	if ((uint64_t)(addr & SHF_ALLOC) == (uint64_t)SHF_ALLOC)
	{
		char *p = "A";
		strcat(flags, p);
	}
	if ((uint64_t)(addr & SHF_EXECINSTR) == (uint64_t)SHF_EXECINSTR)
	{
		char *p = "X";
		strcat(flags, p);
	}
	if ((uint64_t)(addr & SHF_MERGE) == (uint64_t)SHF_MERGE)
	{
		char *p = "M";
		strcat(flags, p);
	}
	if ((uint64_t)(addr & SHF_STRINGS) == (uint64_t)SHF_STRINGS)
	{
		char *p = "S";
		strcat(flags, p);
	}
	if ((uint64_t)(addr & SHF_INFO_LINK) == (uint64_t)SHF_INFO_LINK)
	{
		char *p = "I";
		strcat(flags, p);
	}
	if ((uint64_t)(addr & SHF_LINK_ORDER) == (uint64_t)SHF_LINK_ORDER)
	{
		char *p = "L";
		strcat(flags, p);
	}
	if ((uint64_t)(addr & SHF_OS_NONCONFORMING) == (uint64_t)SHF_OS_NONCONFORMING)
	{
		char *p = "O";
		strcat(flags, p);
	}
	if ((uint64_t)(addr & SHF_GROUP) == (uint64_t)SHF_GROUP)
	{
		char *p = "G";
		strcat(flags, p);
	}
	if ((uint64_t)(addr & SHF_TLS) == (uint64_t)SHF_TLS)
	{
		char *p = "T";
		strcat(flags, p);
	}
	if ((uint64_t)(addr & SHF_COMPRESSED) == (uint64_t)SHF_COMPRESSED)
	{
		char *p = "C";
		strcat(flags, p);
	}
	/* Preserved x */

	if ((uint64_t)(addr & SHF_MASKOS) == (uint64_t)SHF_MASKOS)
	{
		char *p = "o";
		strcat(flags, p);
	}
	if ((uint64_t)(addr & SHF_EXCLUDE) == (uint64_t)SHF_EXCLUDE)
	{
		char *p = "E";
		strcat(flags, p);
	}
	/* Preserved l */

	if ((uint64_t)(addr & SHF_MASKPROC) == (uint64_t)SHF_MASKPROC)
	{
		char *p = "p";
		strcat(flags, p);
	}

	printf("%-5s  ", flags); // FLAG
	return ERR_GOOD;
}

STATE_CODE
read32Header(Elf32_Ehdr *header32)
{
	printf("%sELF Header:\n  %sMagic:   ", RED, ORANGE);
	for (int i = 0; i < EI_NIDENT; i++)
		printf("%02x ", header32->e_ident[i]);
	printf("\n  %s%-35sELF32\n", YELLOW, "Class:");
	getDataEncoding(header32->e_ident[EI_DATA]);
	getVersion(header32->e_ident[EI_VERSION]);
	getSystemName(header32->e_ident[EI_OSABI]);
	getABIVersion(header32->e_ident[EI_ABIVERSION]);
	getType(header32->e_type);
	getMachine(header32->e_machine);
	getVersionHex(header32->e_version);
	getEntry(header32->e_entry);
	getPhoff(header32->e_phoff);
	getShoff(header32->e_shoff);
	getFlags(header32->e_flags);
	getEhsize(header32->e_ehsize);
	getPhentsize(header32->e_phentsize);
	getPhnum(header32->e_phnum);
	getShentsize(header32->e_shentsize);
	getShnum(header32->e_shnum);
	getShstrndx(header32->e_shstrndx);
	return ERR_GOOD;
}

STATE_CODE
read64Header(Elf64_Ehdr *header64)
{
	printf("%sELF Header:\n  %sMagic:   ", RED, ORANGE);
	for (int i = 0; i < EI_NIDENT; i++)
		printf("%02x ", header64->e_ident[i]);
	printf("\n  %s%-35sELF64\n", YELLOW, "Class:");
	getDataEncoding(header64->e_ident[EI_DATA]);
	getVersion(header64->e_ident[EI_VERSION]);
	getSystemName(header64->e_ident[EI_OSABI]);
	getABIVersion(header64->e_ident[EI_ABIVERSION]);
	getType(header64->e_type);
	getMachine(header64->e_machine);
	getVersionHex(header64->e_version);
	getEntry(header64->e_entry);
	getPhoff(header64->e_phoff);
	getShoff(header64->e_shoff);
	getFlags(header64->e_flags);
	getEhsize(header64->e_ehsize);
	getPhentsize(header64->e_phentsize);
	getPhnum(header64->e_phnum);
	getShentsize(header64->e_shentsize);
	getShnum(header64->e_shnum);
	getShstrndx(header64->e_shstrndx);
	return ERR_GOOD;
}

STATE_CODE read32Section(Elf32_Ehdr *header32)
{
	printf("%sThere are %hu section headers, starting at offset 0x%x:\n\n", GREY250, header32->e_shnum, header32->e_shoff);
	printf("Section Headers:\n");
	printf("  [%2s] %-18s  %-17s %-18s %s\n","Nr", "Name", "Type", "Address", "Offset");
	printf("       %-18s  %-17s Flags  Link  Info  Align\n", "Size", "EntSize");

	Elf32_Shdr *section_header = (Elf32_Shdr *)((char *)header32 + header32->e_shoff);

	char *shstrtab = (char *)header32 + section_header[header32->e_shstrndx].sh_offset;
	int num_header = header32->e_shnum;

	for (int i = 0; i < num_header; i++)
	{
		printf("%s", rainbow(i % 7));
		printf("  [%s%2hu%s] %-18s  ",KIRAKIRA, i,KIRADAME, shstrtab + section_header[i].sh_name);
		getShtype(section_header[i].sh_type);
		printf(" %016x   ", section_header[i].sh_addr);
		printf("%08x\n", section_header[i].sh_offset);
		printf("       %016x    %016x  ", section_header[i].sh_size, section_header[i].sh_entsize);
		getSectionFlag(section_header[i].sh_flags);
		printf("%-4d  %-4d  %-3x \n", section_header[i].sh_link, section_header[i].sh_info, section_header[i].sh_addralign);
	}

	printf("%sKey to Flags:\n", GREY250);
	printf("  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),\n");
	printf("  L (link order), O (extra OS processing required), G (group), T (TLS),\n");
	printf("  C (compressed), x (unknown), o (OS specific), E (exclude),\n");
	printf("  l (large), p (processor specific)\n");
	return ERR_GOOD;
}

STATE_CODE read64Section(Elf64_Ehdr *header64)
{
	printf("%sThere are %hu section headers, starting at offset 0x%lx:\n\n", GREY250, header64->e_shnum, header64->e_shoff);
	printf("Section Headers:\n");
	printf("  [%2s] %-18s  %-17s %-18s %s\n","Nr","Name", "Type", "Address", "Offset");
	printf("       %-18s  %-17s Flags  Link  Info  Align\n", "Size", "EntSize");

	Elf64_Shdr *section_header = (Elf64_Shdr *)((char *)header64 + header64->e_shoff);

	char *shstrtab = (char *)header64 + section_header[header64->e_shstrndx].sh_offset;
	int num_header = header64->e_shnum;

	for (int i = 0; i < num_header; i++)
	{
		printf("%s", rainbow(i % 7));
		printf("  [%s%2hu%s] %-18s  ", KIRAKIRA,i, KIRADAME,shstrtab + section_header[i].sh_name);
		getShtype(section_header[i].sh_type);
		printf(" %016lx   ", section_header[i].sh_addr);
		printf("%08lx\n", section_header[i].sh_offset);
		printf("       %016lx    %016lx  ", section_header[i].sh_size, section_header[i].sh_entsize);
		getSectionFlag(section_header[i].sh_flags);
		printf("%-4d  %-4d  %-3lx \n", section_header[i].sh_link, section_header[i].sh_info, section_header[i].sh_addralign);
	}

	printf("%sKey to Flags:\n", GREY250);
	printf("  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),\n");
	printf("  L (link order), O (extra OS processing required), G (group), T (TLS),\n");
	printf("  C (compressed), x (unknown), o (OS specific), E (exclude),\n");
	printf("  l (large), p (processor specific)\n");
	return ERR_GOOD;
}

STATE_CODE read32Symtab(Elf32_Ehdr *header32)
{
	Elf32_Shdr *section_header = (Elf32_Shdr *)((char *)header32 + header32->e_shoff);

	char *shstrtab = (char *)header32 + section_header[header32->e_shstrndx].sh_offset;

	unsigned int num_header = header32->e_shnum;

	unsigned int dynsym_shidx; // Dynamic symbol Section header index
	unsigned int symtab_shidx; // Symbol table Section header index
	Elf32_Sym *dynsym = NULL;
	Elf32_Sym *symtab = NULL;

	char *strtab = NULL;
	char *dynstr = NULL;

	/* FIND .strtab */
	for (int i = 0; i < num_header; i++)
	{
		if (strcmp((shstrtab + section_header[i].sh_name), (char *)".strtab") == 0)
		{
			strtab = (char *)header32 + section_header[i].sh_offset;
			break;
		}
	}
	assert(strtab);

	/* FIND .dynstr */
	for (int i = 0; i < num_header; i++)
	{
		if (strcmp((shstrtab + section_header[i].sh_name), (char *)".dynstr") == 0)
		{
			dynstr = (char *)header32 + section_header[i].sh_offset;
			break;
		}
	}
	assert(dynstr);
	/* FIND .dynsym */
	for (int i = 0; i < num_header; i++)
	{
		if (strcmp((shstrtab + section_header[i].sh_name), (char *)".dynsym") == 0)
		{
			dynsym = (Elf32_Sym *)((char *)header32 + section_header[i].sh_offset);
			dynsym_shidx = i;
			break;
		}
	}
	assert(dynsym);
	/* FIND .symtab */
	for (int i = 0; i < num_header; i++)
	{
		if (strcmp((shstrtab + section_header[i].sh_name), (char *)".symtab") == 0)
		{
			symtab = (Elf32_Sym *)((char *)header32 + section_header[i].sh_offset);
			symtab_shidx = i;
			break;
		}
	}
	assert(symtab);

	unsigned int dynsym_num_entries = (unsigned int)(section_header[dynsym_shidx].sh_size / section_header[dynsym_shidx].sh_entsize);

	printf("%sSymbol table '%s' contains %d entries:\n",GREY250, shstrtab + section_header[dynsym_shidx].sh_name, dynsym_num_entries);
	printf("%7s %s %5s %-7s %-6s %-8s %3s %s\n", "Num:", "   Value        ", "Size", "Type", "Bind", "Vis", "Ndx", "Name");
	for (unsigned int i = 0; i < dynsym_num_entries; i++)
	{
		printf("%s", rainbow(i % 7));
		printf("%s%6d%s:",KIRAKIRA, i,KIRADAME);					  // Num
		printf(" %016x", dynsym[i].st_value); // Value
		printf(" %5d", dynsym[i].st_size);	  // Size
		getStentrytype(ELF32_ST_TYPE(dynsym[i].st_info));
		getStentrybind(ELF32_ST_BIND(dynsym[i].st_info));
		getStentryvis(ELF32_ST_VISIBILITY(dynsym[i].st_other));
		getStentryNdx(dynsym[i].st_shndx);
		printf(" %s", dynstr + dynsym[i].st_name); // Name
		printf("\n");
	}

	unsigned int symtab_num_entries = (unsigned int)(section_header[symtab_shidx].sh_size / section_header[symtab_shidx].sh_entsize);
	printf("%sSymbol table '%s' contains %d entries:\n", GREY250,shstrtab + section_header[symtab_shidx].sh_name, symtab_num_entries);
	printf("%7s %s %5s %-7s %-6s %-8s %3s %s\n", "Num:", "   Value        ", "Size", "Type", "Bind", "Vis", "Ndx", "Name");
	for (unsigned int i = 0; i < symtab_num_entries; i++)
	{
		printf("%s", rainbow(i % 7));
		printf("%s%6d%s:",KIRAKIRA, i,KIRADAME);					  // Num
		printf(" %016x", symtab[i].st_value); // Value
		printf(" %5d", symtab[i].st_size);	  // Size
		getStentrytype(ELF32_ST_TYPE(symtab[i].st_info));
		getStentrybind(ELF32_ST_BIND(symtab[i].st_info));
		getStentryvis(ELF32_ST_VISIBILITY(symtab[i].st_other));
		getStentryNdx(symtab[i].st_shndx);
		printf(" %s", strtab + symtab[i].st_name); // Name
		printf("\n");
	}
	return ERR_GOOD;
}
STATE_CODE read64Symtab(Elf64_Ehdr *header64)
{
	Elf64_Shdr *section_header = (Elf64_Shdr *)((char *)header64 + header64->e_shoff);

	char *shstrtab = (char *)header64 + section_header[header64->e_shstrndx].sh_offset;

	unsigned int num_header = header64->e_shnum;

	unsigned int dynsym_shidx; // Dynamic symbol Section header index
	unsigned int symtab_shidx; // Symbol table Section header index
	Elf64_Sym *dynsym = NULL;
	Elf64_Sym *symtab = NULL;

	char *strtab = NULL;
	char *dynstr = NULL;
	/* FIND .strtab */
	for (int i = 0; i < num_header; i++)
	{
		if (strcmp((shstrtab + section_header[i].sh_name), (char *)".strtab") == 0)
		{
			strtab = (char *)header64 + section_header[i].sh_offset;
			break;
		}
	}
	assert(strtab);

	/* FIND .dynstr */
	for (int i = 0; i < num_header; i++)
	{
		if (strcmp((shstrtab + section_header[i].sh_name), (char *)".dynstr") == 0)
		{
			dynstr = (char *)header64 + section_header[i].sh_offset;
			break;
		}
	}
	assert(dynstr);
	/* FIND .dynsym */
	for (int i = 0; i < num_header; i++)
	{
		if (strcmp((shstrtab + section_header[i].sh_name), (char *)".dynsym") == 0)
		{
			dynsym = (Elf64_Sym *)((char *)header64 + section_header[i].sh_offset);
			dynsym_shidx = i;
			break;
		}
	}
	assert(dynsym);
	/* FIND .symtab */
	for (int i = 0; i < num_header; i++)
	{
		if (strcmp((shstrtab + section_header[i].sh_name), (char *)".symtab") == 0)
		{
			symtab = (Elf64_Sym *)((char *)header64 + section_header[i].sh_offset);
			symtab_shidx = i;
			break;
		}
	}
	assert(symtab);

	unsigned int dynsym_num_entries = (unsigned int)(section_header[dynsym_shidx].sh_size / section_header[dynsym_shidx].sh_entsize);

	printf("%sSymbol table '%s' contains %d entries:\n",GREY250, shstrtab + section_header[dynsym_shidx].sh_name, dynsym_num_entries);
	printf("%7s %s %5s %-7s %-6s %-8s %3s %s\n", "Num:", "   Value        ", "Size", "Type", "Bind", "Vis", "Ndx", "Name");
	for (unsigned int i = 0; i < dynsym_num_entries; i++)
	{
		printf("%s", rainbow(i % 7));
		printf("%s%6d%s:",KIRAKIRA, i,KIRADAME);					   // Num
		printf(" %016lx", dynsym[i].st_value); // Value
		printf(" %5ld", dynsym[i].st_size);	   // Size
		getStentrytype(ELF64_ST_TYPE(dynsym[i].st_info));
		getStentrybind(ELF64_ST_BIND(dynsym[i].st_info));
		getStentryvis(ELF64_ST_VISIBILITY(dynsym[i].st_other));
		getStentryNdx(dynsym[i].st_shndx);
		printf(" %s", dynstr + dynsym[i].st_name); // Name
		printf("\n");
	}

	unsigned int symtab_num_entries = (unsigned int)(section_header[symtab_shidx].sh_size / section_header[symtab_shidx].sh_entsize);
	printf("%sSymbol table '%s' contains %d entries:\n", GREY250,shstrtab + section_header[symtab_shidx].sh_name, symtab_num_entries);
	printf("%7s %s %5s %-7s %-6s %-8s %3s %s\n", "Num:", "   Value        ", "Size", "Type", "Bind", "Vis", "Ndx", "Name");
	for (unsigned int i = 0; i < symtab_num_entries; i++)
	{
		printf("%s", rainbow(i % 7));
		printf("%s%6d%s:",KIRAKIRA, i,KIRADAME);// Num
		printf(" %016lx", symtab[i].st_value); // Value
		printf(" %5ld", symtab[i].st_size);	   // Size
		getStentrytype(ELF64_ST_TYPE(symtab[i].st_info));
		getStentrybind(ELF64_ST_BIND(symtab[i].st_info));
		getStentryvis(ELF64_ST_VISIBILITY(symtab[i].st_other));
		getStentryNdx(symtab[i].st_shndx);
		printf(" %s", strtab + symtab[i].st_name); // Name
		printf("\n");
	}

	return ERR_GOOD;
}

STATE_CODE getStentryNdx(uint16_t code)
{
	switch (code)
	{
	case SHN_UNDEF:
		printf(" %3s", "UND");
		break;

	case SHN_ABS:
		printf(" %3s", "ABS");
		break;

	case SHN_COMMON:
		printf(" %3s", "COM");
		break;

	default:
		printf(" %3d", code);
		break;
	}
}

STATE_CODE getStentryvis(unsigned char code)
{
	switch (code)
	{
	case STV_DEFAULT:
		printf(" %-8s", "DEFAULT");
		break;

	case STV_INTERNAL:
		printf(" %-8s", "INTERNAL");
		break;

	case STV_HIDDEN:
		printf(" %-8s", "HIDDEN");
		break;

	case STV_PROTECTED:
		printf(" %-8s", "PROTECTED");
		break;

	default:
		break;
	}
}

STATE_CODE getStentrybind(unsigned char code)
{
	switch (code)
	{
	case STB_LOCAL:
		printf(" %-6s", "LOCAL");
		break;

	case STB_GLOBAL:
		printf(" %-6s", "GLOBAL");
		break;

	case STB_WEAK:
		printf(" %-6s", "WEAK");
		break;

	case STB_NUM:
		printf(" %-6s", "NUM");
		break;

	case STB_LOOS:
		printf(" %-6s", "LOOS");
		break;

	case STB_HIOS:
		printf(" %-6s", "HIOS");
		break;

	case STB_LOPROC:
		printf(" %-6s", "LOPROC");
		break;

	case STB_HIPROC:
		printf(" %-6s", "HIPROC");
		break;

	default:
		break;
	}
}

STATE_CODE getStentrytype(unsigned char code)
{
	switch (code)
	{
	case STT_NOTYPE:
		printf(" %-7s", "NOTYPE");
		break;

	case STT_OBJECT:
		printf(" %-7s", "OBJECT");
		break;

	case STT_FUNC:
		printf(" %-7s", "FUNC");
		break;

	case STT_SECTION:
		printf(" %-7s", "SECTION");
		break;

	case STT_FILE:
		printf(" %-7s", "FILE");
		break;

	case STT_COMMON:
		printf(" %-7s", "COMMON");
		break;

	case STT_TLS:
		printf(" %-7s", "TLS");
		break;

	case STT_NUM:
		printf(" %-7s", "NUM");
		break;

	case STT_LOOS:
		printf(" %-7s", "LOOS");
		break;

	case STT_HIOS:
		printf(" %-7s", "HIOS");
		break;

	case STT_LOPROC:
		printf(" %-7s", "LOPROC");
		break;

	case STT_HIPROC:
		printf(" %-7s", "HIPROC");
		break;

	default:
		break;
	}
}

STATE_CODE
fileHeader(char *buffer)
{
	Elf32_Ehdr *header32;
	Elf64_Ehdr *header64;
	ELF_CLASS procType;
	header32 = (Elf32_Ehdr *)buffer;
	header64 = (Elf64_Ehdr *)buffer;
#if __WORDSIZE == 64
	procType = getClass(header64);
#else
	procType = getClass(header32);
#endif
	if (procType == ELF_32_BIT)
	{
		STATE_CODE flag32 = ERR_UNKNOWN;
		if (readelf_flags[READELF_HEADER])
		{
			flag32 = readHeader(header32);
		}

		if (readelf_flags[READELF_SECTION])
		{
			flag32 = readSection(header32);
		}

		if (readelf_flags[READELF_SYMBOL])
		{
			flag32 = readSymtab(header32);
		}

		if (flag32 == ERR_UNKNOWN)
			printf("UNKNOWN ERROR\n");
		return flag32;
	}

	else if (procType == ELF_64_BIT)
	{
		STATE_CODE flag64 = ERR_UNKNOWN;
		if (readelf_flags[READELF_HEADER])
		{
			flag64 = readHeader(header64);
		}

		if (readelf_flags[READELF_SECTION])
		{
			flag64 = readSection(header64);
		}

		if (readelf_flags[READELF_SYMBOL])
		{
			flag64 = readSymtab(header64);
		}

		if (flag64 == ERR_UNKNOWN)
			printf("UNKNOWN ERROR\n");
		return flag64;
	}
	else
		return ERR_UNKNOWN;
}

char *rainbow(int index)
{
	switch (index)
	{
	case 0:
		return RED;
		break;
	case 1:
		return ORANGE;
		break;
	case 2:
		return YELLOW;
		break;
	case 3:
		return GREEN;
		break;
	case 4:
		return CYAN;
		break;
	case 5:
		return BLUE;
		break;
	case 6:
		return PURPLE;
		break;
	default:
		return GREY250;
		break;
	}
}