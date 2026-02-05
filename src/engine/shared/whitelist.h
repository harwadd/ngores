#ifndef ENGINE_SHARED_WHITELIST_H
#define ENGINE_SHARED_WHITELIST_H

#include <base/system.h>
#include <engine/console.h>
#include <engine/storage.h>

class CWhitelist
{
private:
	class IConsole *m_pConsole;
	class IStorage *m_pStorage;
	
	struct CWhitelistEntry
	{
		NETADDR m_Addr;
		CWhitelistEntry *m_pNext;
		CWhitelistEntry *m_pPrev;
	};
	
	CWhitelistEntry *m_pFirstEntry;
	int m_Count;
	
	bool NetMatch(const NETADDR *pAddr1, const NETADDR *pAddr2) const;
	const char *NetToString(const NETADDR *pData, char *pBuffer, unsigned BufferSize) const;
	
public:
	CWhitelist();
	void Init(class IConsole *pConsole, class IStorage *pStorage);
	
	bool Add(const NETADDR *pAddr);
	bool Remove(const NETADDR *pAddr);
	void Clear();
	bool IsWhitelisted(const NETADDR *pAddr) const;
	
	int Count() const { return m_Count; }
	
	void Save();
	void Load();
	
	static void ConAdd(class IConsole::IResult *pResult, void *pUser);
	static void ConRemove(class IConsole::IResult *pResult, void *pUser);
	static void ConClear(class IConsole::IResult *pResult, void *pUser);
	static void ConList(class IConsole::IResult *pResult, void *pUser);
	static void ConWelcome(class IConsole::IResult *pResult, void *pUser);
};

extern CWhitelist g_Whitelist;

#endif // ENGINE_SHARED_WHITELIST_H
