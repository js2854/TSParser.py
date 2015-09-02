# TSParser.py
Python实现的一个解析MPEG-TS的小程序，解析PAT,PMT,PCR,PTS,DTS等信息

## Usage

	usage: TSParser.py [-h] [-p PID] [-g GREP] filepath

	positional arguments:
	  filepath              The mpeg-ts file

	optional arguments:
	  -h, --help            show this help message and exit
	  -p PID, --pid PID     Only show the specific pid
	  -g GREP, --grep GREP  Show the specific package type, default is
	                        "PAT,PMT,PCR,PTS,DTS"

## Demo

	D:\git\TSParser.py>python TSParser.py demo.ts -p 0x0
	Open file<demo.ts> success.
	Seek to first packet, offset: 0x00000000
	PktNo: 00000016, Offset: 0x00000BC0, PID: 0x0000, CC: 01 , PAT
	PktNo: 00000480, Offset: 0x00016080, PID: 0x0000, CC: 02 , PAT
	PktNo: 00000960, Offset: 0x0002C100, PID: 0x0000, CC: 03 , PAT
	PktNo: 00001440, Offset: 0x00042180, PID: 0x0000, CC: 04 , PAT
	PktNo: 00001920, Offset: 0x00058200, PID: 0x0000, CC: 05 , PAT
	PktNo: 00002400, Offset: 0x0006E280, PID: 0x0000, CC: 06 , PAT
	PktNo: 00002880, Offset: 0x00084300, PID: 0x0000, CC: 07 , PAT
	PktNo: 00003360, Offset: 0x0009A380, PID: 0x0000, CC: 08 , PAT
	PktNo: 00003840, Offset: 0x000B0400, PID: 0x0000, CC: 09 , PAT
	Parse file complete!
	Close file<demo.ts>
	D:\git\TSParser.py>
	D:\git\TSParser.py>python TSParser.py demo.ts -g PMT
	Open file<demo.ts> success.
	Seek to first packet, offset: 0x00000000
	PktNo: 00000017, Offset: 0x00000C7C, PID: 0x0500, CC: 01 , PMT
	PktNo: 00000481, Offset: 0x0001613C, PID: 0x0500, CC: 02 , PMT
	PktNo: 00000961, Offset: 0x0002C1BC, PID: 0x0500, CC: 03 , PMT
	PktNo: 00001441, Offset: 0x0004223C, PID: 0x0500, CC: 04 , PMT
	PktNo: 00001921, Offset: 0x000582BC, PID: 0x0500, CC: 05 , PMT
	PktNo: 00002401, Offset: 0x0006E33C, PID: 0x0500, CC: 06 , PMT
	PktNo: 00002881, Offset: 0x000843BC, PID: 0x0500, CC: 07 , PMT
	PktNo: 00003361, Offset: 0x0009A43C, PID: 0x0500, CC: 08 , PMT
	PktNo: 00003841, Offset: 0x000B04BC, PID: 0x0500, CC: 09 , PMT
	Parse file complete!
	Close file<demo.ts>