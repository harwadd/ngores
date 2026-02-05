#include <base/system.h>
#include <engine/console.h>
#include <engine/storage.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "linereader.h"
#include "whitelist.h"

CWhitelist g_Whitelist;

CWhitelist::CWhitelist()
{
	m_pConsole = 0;
	m_pStorage = 0;
	m_pFirstEntry = 0;
	m_Count = 0;
}

bool CWhitelist::NetMatch(const NETADDR *pAddr1, const NETADDR *pAddr2) const
{
	if(pAddr1->type != pAddr2->type)
		return false;
	
	if(pAddr1->type == NETTYPE_IPV4 || pAddr1->type == NETTYPE_WEBSOCKET_IPV4)
		return mem_comp(pAddr1->ip, pAddr2->ip, 4) == 0;
	else if(pAddr1->type == NETTYPE_IPV6)
		return mem_comp(pAddr1->ip, pAddr2->ip, 16) == 0;
	
	return false;
}

const char *CWhitelist::NetToString(const NETADDR *pData, char *pBuffer, unsigned BufferSize) const
{
	char aAddrStr[NETADDR_MAXSTRSIZE];
	net_addr_str(pData, aAddrStr, sizeof(aAddrStr), false);
	str_format(pBuffer, BufferSize, "'%s'", aAddrStr);
	return pBuffer;
}

void CWhitelist::Init(IConsole *pConsole, IStorage *pStorage)
{
	m_pConsole = pConsole;
	m_pStorage = pStorage;
	
	// Register console commands
	m_pConsole->Register("whitelist_add", "s[ip]", CFGFLAG_SERVER | CFGFLAG_STORE, ConAdd, this, "Add IP to whitelist");
	m_pConsole->Register("whitelist_remove", "s[ip]", CFGFLAG_SERVER | CFGFLAG_STORE, ConRemove, this, "Remove IP from whitelist");
	m_pConsole->Register("whitelist_clear", "", CFGFLAG_SERVER | CFGFLAG_STORE, ConClear, this, "Clear all whitelist entries");
	m_pConsole->Register("whitelist_list", "", CFGFLAG_SERVER, ConList, this, "List all whitelisted IPs");
	m_pConsole->Register("whitelist_welcome", "", CFGFLAG_SERVER, ConWelcome, this, "Display welcome message");
	
	// load saved whitelist
	Load();
}

bool CWhitelist::Add(const NETADDR *pAddr)
{
	// check if already exists
	for(CWhitelistEntry *pEntry = m_pFirstEntry; pEntry; pEntry = pEntry->m_pNext)
	{
		if(NetMatch(&pEntry->m_Addr, pAddr))
			return false; // already exists
	}
	
	// create new entry
	CWhitelistEntry *pEntry = (CWhitelistEntry *)malloc(sizeof(CWhitelistEntry));
	if(!pEntry)
		return false;
	
	pEntry->m_Addr = *pAddr;
	pEntry->m_pNext = m_pFirstEntry;
	pEntry->m_pPrev = 0;
	
	if(m_pFirstEntry)
		m_pFirstEntry->m_pPrev = pEntry;
	
	m_pFirstEntry = pEntry;
	m_Count++;
	
	// save to file
	Save();
	
	return true;
}

bool CWhitelist::Remove(const NETADDR *pAddr)
{
	for(CWhitelistEntry *pEntry = m_pFirstEntry; pEntry; pEntry = pEntry->m_pNext)
	{
		if(NetMatch(&pEntry->m_Addr, pAddr))
		{
			// remove from list
			if(pEntry->m_pPrev)
				pEntry->m_pPrev->m_pNext = pEntry->m_pNext;
			else
				m_pFirstEntry = pEntry->m_pNext;
			
			if(pEntry->m_pNext)
				pEntry->m_pNext->m_pPrev = pEntry->m_pPrev;
			
			free(pEntry);
			m_Count--;
			
			// save to file
			Save();
			
			return true;
		}
	}
	
	return false;
}

void CWhitelist::Clear()
{
	CWhitelistEntry *pEntry = m_pFirstEntry;
	while(pEntry)
	{
		CWhitelistEntry *pNext = pEntry->m_pNext;
		free(pEntry);
		pEntry = pNext;
	}
	
	m_pFirstEntry = 0;
	m_Count = 0;
	
	// save to file
	Save();
}

bool CWhitelist::IsWhitelisted(const NETADDR *pAddr) const
{
	for(CWhitelistEntry *pEntry = m_pFirstEntry; pEntry; pEntry = pEntry->m_pNext)
	{
		if(NetMatch(&pEntry->m_Addr, pAddr))
			return true;
	}
	
	return false;
}

void CWhitelist::Save()
{
	char aBuf[256];
	IOHANDLE File = m_pStorage->OpenFile("whitelist.cfg", IOFLAG_WRITE, IStorage::TYPE_SAVE);
	if(!File)
		return;
	
	for(CWhitelistEntry *pEntry = m_pFirstEntry; pEntry; pEntry = pEntry->m_pNext)
	{
		char aAddrStr[NETADDR_MAXSTRSIZE];
		net_addr_str(&pEntry->m_Addr, aAddrStr, sizeof(aAddrStr), false);
		str_format(aBuf, sizeof(aBuf), "whitelist_add %s", aAddrStr);
		io_write(File, aBuf, str_length(aBuf));
		io_write_newline(File);
	}
	
	io_close(File);
}

void CWhitelist::Load()
{
	IOHANDLE File = m_pStorage->OpenFile("whitelist.cfg", IOFLAG_READ, IStorage::TYPE_SAVE);
	if(!File)
		return;

	CLineReader LineReader;
	LineReader.OpenFile(File);

	const char *pLine;
	while((pLine = LineReader.Get()))
	{
		// Parse line
		char aCmd[64], aAddrStr[64];
		if(sscanf(pLine, "%63s %63s", aCmd, aAddrStr) == 2 && str_comp(aCmd, "whitelist_add") == 0)
		{
			NETADDR Addr;
			if(net_addr_from_str(&Addr, aAddrStr) == 0)
				Add(&Addr);
		}
	}
}

void CWhitelist::ConAdd(IConsole::IResult *pResult, void *pUser)
{
	CWhitelist *pThis = static_cast<CWhitelist *>(pUser);
	
	const char *pStr = pResult->GetString(0);
	NETADDR Addr;
	if(net_addr_from_str(&Addr, pStr) == 0)
	{
		if(pThis->Add(&Addr))
		{
			char aBuf[256];
			pThis->NetToString(&Addr, aBuf, sizeof(aBuf));
			pThis->m_pConsole->Print(IConsole::OUTPUT_LEVEL_STANDARD, "whitelist", aBuf);
		}
		else
			pThis->m_pConsole->Print(IConsole::OUTPUT_LEVEL_STANDARD, "whitelist", "IP already in whitelist");
	}
	else
		pThis->m_pConsole->Print(IConsole::OUTPUT_LEVEL_STANDARD, "whitelist", "Invalid IP address");
}

void CWhitelist::ConRemove(IConsole::IResult *pResult, void *pUser)
{
	CWhitelist *pThis = static_cast<CWhitelist *>(pUser);
	
	const char *pStr = pResult->GetString(0);
	NETADDR Addr;
	if(net_addr_from_str(&Addr, pStr) == 0)
	{
		if(pThis->Remove(&Addr))
		{
			char aBuf[256];
			pThis->NetToString(&Addr, aBuf, sizeof(aBuf));
			pThis->m_pConsole->Print(IConsole::OUTPUT_LEVEL_STANDARD, "whitelist", aBuf);
		}
		else
			pThis->m_pConsole->Print(IConsole::OUTPUT_LEVEL_STANDARD, "whitelist", "IP not found in whitelist");
	}
	else
		pThis->m_pConsole->Print(IConsole::OUTPUT_LEVEL_STANDARD, "whitelist", "Invalid IP address");
}

void CWhitelist::ConClear(IConsole::IResult *pResult, void *pUser)
{
	CWhitelist *pThis = static_cast<CWhitelist *>(pUser);
	pThis->Clear();
	pThis->m_pConsole->Print(IConsole::OUTPUT_LEVEL_STANDARD, "whitelist", "Whitelist cleared");
}

void CWhitelist::ConList(IConsole::IResult *pResult, void *pUser)
{
	CWhitelist *pThis = static_cast<CWhitelist *>(pUser);
	
	if(pThis->m_Count == 0)
	{
		pThis->m_pConsole->Print(IConsole::OUTPUT_LEVEL_STANDARD, "whitelist", "Whitelist is empty");
		return;
	}
	
	char aBuf[256], aMsg[256];
	int Count = 0;
	for(CWhitelistEntry *pEntry = pThis->m_pFirstEntry; pEntry; pEntry = pEntry->m_pNext, Count++)
	{
		pThis->NetToString(&pEntry->m_Addr, aBuf, sizeof(aBuf));
		str_format(aMsg, sizeof(aMsg), "#%d %s", Count, aBuf);
		pThis->m_pConsole->Print(IConsole::OUTPUT_LEVEL_STANDARD, "whitelist", aMsg);
	}
	
	str_format(aMsg, sizeof(aMsg), "%d %s in whitelist", pThis->m_Count, pThis->m_Count == 1 ? "entry" : "entries");
	pThis->m_pConsole->Print(IConsole::OUTPUT_LEVEL_STANDARD, "whitelist", aMsg);
}

void CWhitelist::ConWelcome(IConsole::IResult *pResult, void *pUser)
{
	CWhitelist *pThis = static_cast<CWhitelist *>(pUser);

	// log request metadata: command as method, empty arguments as path
	pThis->m_pConsole->Print(IConsole::OUTPUT_LEVEL_STANDARD, "whitelist", "Request: method=whitelist_welcome, path=");

	// print JSON response
	pThis->m_pConsole->Print(IConsole::OUTPUT_LEVEL_STANDARD, "whitelist", "{\"message\": \"Welcome to the whitelist!\"}");
}
