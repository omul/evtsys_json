/*
  Copyright (c) 2009, Rochester Institute of Technology
  All rights reserved.

  Redistribution and use in source and binary forms are permitted provided
  that:

  (1) source distributions retain this entire copyright notice and comment,
      and
  (2) distributions including binaries display the following acknowledgement:

         "This product includes software developed by Rochester Institute of Technology."

      in the documentation or other materials provided with the distribution
      and in all advertising materials mentioning features or use of this
      software.

  The name of the University may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  This software contains code taken from the Eventlog to Syslog service
  developed by Curtis Smith of Purdue University.

  THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
  WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.

  This software was developed by:
     Sherwin Faria

     Rochester Institute of Technology
     Information and Technology Services
     1 Lomb Memorial Drive, Bldg 10
     Rochester, NY 14623 U.S.A.

  Send all comments, suggestions, or bug reports to:
     sherwin.faria@gmail.com

*/
#include "main.h"
#include <malloc.h>
#include <wchar.h>
#include <winevt.h>
#include <winmeta.h>
#include "log.h"
#include "service.h"
#include "syslog.h"
#include "winevent.h"
#include "plugin-login.h"
#include "check.h"

#pragma comment(lib, "delayimp.lib") /* Prevents winevt from loading unless necessary */
#pragma comment(lib, "wevtapi.lib")	 /* New Windows Events logging library for Vista and beyond */

/* Prototypes */
DWORD ProcessEvent(EVT_HANDLE hEvent, PVOID pContext );
DWORD WINAPI WinEventCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent);

/* Number of eventlogs */
#define WIN_EVENTLOG_SZ		32

/* Eventlog descriptor */
struct WinEventlog {
	WCHAR name[WIN_EVENTLOG_NAME_SZ];	/* Name of eventlog		*/
	HANDLE handle;					/* Handle to eventlog	*/
	int recnum;					/* Next record number		*/
};

int		   subscriptions = 0;
EVT_HANDLE WinEventSub[MAX_SUBSCRIPTIONS];

/* Subscribe to new events */
DWORD WinEventSubscribe(XPathList * xpathQueries, int queryCount)
{
    LPWSTR error_msg = NULL;
    WCHAR * pQueryL;
    DWORD used;
	DWORD status = ERROR_SUCCESS;
	XPathList * iter;

    pQueryL = (WCHAR*)malloc(QUERY_LIST_SZ);
	
	for (iter = xpathQueries; iter != NULL; iter = iter->next) {
		if(!CreateQueryString(pQueryL, iter))
			continue;

		WinEventSub[subscriptions++] = EvtSubscribe(NULL, NULL, NULL, pQueryL, NULL, iter->plugin,
									 (EVT_SUBSCRIBE_CALLBACK)WinEventCallback,
									 EvtSubscribeToFutureEvents);

		error_msg = (LPWSTR)malloc(SYSLOG_DEF_SZ*sizeof(WCHAR));
		
		if (WinEventSub == NULL)
		{
			status = GetLastError();

			if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
				Log(LOG_WARNING, "Channel %s was not found.\n", "Unknown");
			else if (ERROR_EVT_INVALID_QUERY == status)
			{
				Log(LOG_ERROR, "The query \"%S\" is not valid.\n", pQueryL);

				if (EvtGetExtendedStatus(SYSLOG_DEF_SZ, error_msg, &used) == ERROR_SUCCESS)
					Log(LOG_ERROR, "%S", error_msg);
			}
			else
				Log(LOG_ERROR | LOG_SYS, "EvtSubscribe failed with %lu.\n", status);

			WinEventCancelSubscribes();
			status = ERR_FAIL;
		}

	}

	if (pQueryL != NULL)
		free(pQueryL);
    return status;
}

/* Create an XML query string for subscription */
boolean CreateQueryString(WCHAR * pQueryL, XPathList * xpathQueries)
{
    WCHAR query[QUERY_SZ];
    int i = 0;
    
    wcscpy_s(pQueryL, QUERY_LIST_SZ, L"<QueryList>");

	if (xpathQueries->source == NULL) {
		return FALSE;
	}

			swprintf_s(query, QUERY_SZ,
				L"<Query Id=\"%i\" Path=\"%S\">%S</Query>",
				i++,
				xpathQueries->source,
				xpathQueries->query
				);

			wcscat_s(pQueryL, QUERY_LIST_SZ, query);
    
    wcscat_s(pQueryL, QUERY_LIST_SZ, L"</QueryList>");
	return TRUE;
}

/* Cancel the subscription */
void WinEventCancelSubscribes()
{
	while (subscriptions >= 0){
		EvtClose(WinEventSub[subscriptions--]);
	}        
}

/* This function is called whenever a matching event is triggered */
DWORD WINAPI WinEventCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID context, EVT_HANDLE hEvent)
{
    DWORD status = ERROR_SUCCESS;

    switch(action)
    {
        case EvtSubscribeActionError:
            if (ERROR_EVT_QUERY_RESULT_STALE == (DWORD)hEvent)
            {
                Log(LOG_WARNING, "The subscription callback was notified that event records are missing.");
            }
            else
            {
                Log(LOG_WARNING | LOG_SYS, "The subscription callback received the following Win32 error: %lu", (DWORD)hEvent);
            }
            break;

        case EvtSubscribeActionDeliver:
            status = ProcessEvent(hEvent, context);
            break;

        default:
            Log(LOG_WARNING, "SubscriptionCallback: Unknown action.");
    }

    if (status == ERR_FAIL)
    {
		Log(LOG_ERROR | LOG_SYS, "Error sending log message");

        WinEventCancelSubscribes();
        ServiceIsRunning = FALSE;
    }

    return status; // The service ignores the returned status.
}

/*
 * JSON support
 *
 * The Windows Event Log API can render an event as XML.  EventData is
 * intentionally parsed dynamically here, so the program does not need to
 * know the fields of every possible Windows event (4624, 4625, 4688, 4720,
 * etc.) in advance.
 */
static boolean JsonAppend(WCHAR** buffer, size_t* length, size_t* capacity,
	const WCHAR* text)
{
	size_t add;
	WCHAR* newBuffer;
	size_t newCapacity;

	if (text == NULL)
		return TRUE;

	add = wcslen(text);
	if (*length + add + 1 > *capacity) {
		newCapacity = (*capacity == 0) ? 1024 : *capacity;
		while (*length + add + 1 > newCapacity)
			newCapacity *= 2;

		newBuffer = (WCHAR*)realloc(*buffer, newCapacity * sizeof(WCHAR));
		if (newBuffer == NULL)
			return FALSE;

		*buffer = newBuffer;
		*capacity = newCapacity;
	}

	memcpy(*buffer + *length, text, add * sizeof(WCHAR));
	*length += add;
	(*buffer)[*length] = L'\0';
	return TRUE;
}

static boolean JsonAppendChar(WCHAR** buffer, size_t* length,
	size_t* capacity, WCHAR ch)
{
	WCHAR tmp[2];
	tmp[0] = ch;
	tmp[1] = L'\0';
	return JsonAppend(buffer, length, capacity, tmp);
}

/*
 * Append an XML text value as a JSON string value.
 * XML entities commonly occurring in EventData are decoded while escaping
 * characters which have a special meaning in JSON.
 */
static boolean JsonAppendEscapedXml(WCHAR** buffer, size_t* length,
	size_t* capacity, const WCHAR* text)
{
	const WCHAR* p;
	const WCHAR* semi;
	WCHAR entity[16];
	unsigned long value;
	WCHAR ch;

	if (!JsonAppendChar(buffer, length, capacity, L'"'))
		return FALSE;

	if (text != NULL) {
		for (p = text; *p != L'\0'; ++p) {
			ch = *p;

			if (ch == L'&') {
				semi = wcschr(p, L';');
				if (semi != NULL && (size_t)(semi - p) < COUNT_OF(entity)) {
					size_t n = (size_t)(semi - p - 1);
					wcsncpy_s(entity, COUNT_OF(entity), p + 1, n);
					entity[n] = L'\0';

					if (_wcsicmp(entity, L"quot") == 0) {
						if (!JsonAppend(buffer, length, capacity, L"\\\""))
							return FALSE;
						p = semi;
						continue;
					}
					if (_wcsicmp(entity, L"amp") == 0) {
						if (!JsonAppend(buffer, length, capacity, L"&"))
							return FALSE;
						p = semi;
						continue;
					}
					if (_wcsicmp(entity, L"lt") == 0) {
						if (!JsonAppend(buffer, length, capacity, L"<"))
							return FALSE;
						p = semi;
						continue;
					}
					if (_wcsicmp(entity, L"gt") == 0) {
						if (!JsonAppend(buffer, length, capacity, L">"))
							return FALSE;
						p = semi;
						continue;
					}
					if (_wcsicmp(entity, L"apos") == 0) {
						if (!JsonAppend(buffer, length, capacity, L"'"))
							return FALSE;
						p = semi;
						continue;
					}

					if (entity[0] == L'#') {
						value = 0;
						if (entity[1] == L'x' || entity[1] == L'X')
							value = wcstoul(entity + 2, NULL, 16);
						else
							value = wcstoul(entity + 1, NULL, 10);

						if (value != 0 && value <= 0xFFFF) {
							ch = (WCHAR)value;
							p = semi;
						}
					}
				}
			}

			switch (ch) {
			case L'\\':
				if (!JsonAppend(buffer, length, capacity, L"\\\\"))
					return FALSE;
				break;
			case L'"':
				if (!JsonAppend(buffer, length, capacity, L"\\\""))
					return FALSE;
				break;
			case L'\b':
				if (!JsonAppend(buffer, length, capacity, L"\\b"))
					return FALSE;
				break;
			case L'\f':
				if (!JsonAppend(buffer, length, capacity, L"\\f"))
					return FALSE;
				break;
			case L'\n':
				if (!JsonAppend(buffer, length, capacity, L"\\n"))
					return FALSE;
				break;
			case L'\r':
				if (!JsonAppend(buffer, length, capacity, L"\\r"))
					return FALSE;
				break;
			case L'\t':
				if (!JsonAppend(buffer, length, capacity, L"\\t"))
					return FALSE;
				break;
			default:
				if (ch < 0x20) {
					WCHAR escaped[7];
					_snwprintf_s(escaped, COUNT_OF(escaped), _TRUNCATE,
						L"\\u%04x", (unsigned int)ch);
					if (!JsonAppend(buffer, length, capacity, escaped))
						return FALSE;
				}
				else if (!JsonAppendChar(buffer, length, capacity, ch)) {
					return FALSE;
				}
				break;
			}
		}
	}

	return JsonAppendChar(buffer, length, capacity, L'"');
}

static boolean JsonAppendUInt64(WCHAR** buffer, size_t* length,
	size_t* capacity, ULONGLONG value)
{
	WCHAR tmp[32];
	_snwprintf_s(tmp, COUNT_OF(tmp), _TRUNCATE, L"%llu",
		(unsigned long long)value);
	return JsonAppend(buffer, length, capacity, tmp);
}

static boolean JsonAppendInt(WCHAR** buffer, size_t* length,
	size_t* capacity, int value)
{
	WCHAR tmp[32];
	_snwprintf_s(tmp, COUNT_OF(tmp), _TRUNCATE, L"%d", value);
	return JsonAppend(buffer, length, capacity, tmp);
}

/*
 * Extract <EventData><Data Name="...">value</Data>...</EventData>
 * from the event XML.  Fields without a Name attribute are exported as
 * Data0, Data1, ... .  UserData is deliberately left untouched for now.
 */
static boolean JsonAppendEventData(WCHAR** buffer, size_t* length,
	size_t* capacity, const WCHAR* xml)
{
	const WCHAR* section;
	const WCHAR* sectionEnd;
	const WCHAR* p;
	const WCHAR* tagEnd;
	const WCHAR* valueEnd;
	const WCHAR* nameStart;
	const WCHAR* nameEnd;
	WCHAR* name = NULL;
	WCHAR* value = NULL;
	size_t valueLen;
	size_t nameLen;
	int unnamed = 0;
	boolean first = TRUE;
	boolean ok = TRUE;

	section = wcsstr(xml, L"<EventData");
	if (section == NULL)
		return JsonAppend(buffer, length, capacity, L"");

	tagEnd = wcschr(section, L'>');
	if (tagEnd == NULL)
		return TRUE;

	sectionEnd = wcsstr(tagEnd + 1, L"</EventData>");
	if (sectionEnd == NULL)
		return TRUE;

	p = tagEnd + 1;
	while (p < sectionEnd) {
		p = wcsstr(p, L"<Data");
		if (p == NULL || p >= sectionEnd)
			break;

		tagEnd = wcschr(p, L'>');
		if (tagEnd == NULL || tagEnd >= sectionEnd)
			break;

		name = NULL;
		nameStart = wcsstr(p, L"Name=");
		if (nameStart != NULL && nameStart < tagEnd) {
			nameStart += 5;
			if (*nameStart == L'"' || *nameStart == L'\'') {
				WCHAR quote = *nameStart++;
				nameEnd = wcschr(nameStart, quote);
				if (nameEnd != NULL && nameEnd < tagEnd) {
					nameLen = (size_t)(nameEnd - nameStart);
					name = (WCHAR*)malloc((nameLen + 1) * sizeof(WCHAR));
					if (name == NULL) {
						ok = FALSE;
						break;
					}
					wcsncpy_s(name, nameLen + 1, nameStart, nameLen);
					name[nameLen] = L'\0';
				}
			}
		}

		valueEnd = wcsstr(tagEnd + 1, L"</Data>");
		if (valueEnd == NULL || valueEnd > sectionEnd) {
			if (name) free(name);
			break;
		}

		valueLen = (size_t)(valueEnd - (tagEnd + 1));
		value = (WCHAR*)malloc((valueLen + 1) * sizeof(WCHAR));
		if (value == NULL) {
			if (name) free(name);
			ok = FALSE;
			break;
		}
		wcsncpy_s(value, valueLen + 1, tagEnd + 1, valueLen);
		value[valueLen] = L'\0';

		if (!first && !JsonAppend(buffer, length, capacity, L",")) {
			ok = FALSE;
			free(value);
			if (name) free(name);
			break;
		}
		first = FALSE;

		if (name == NULL) {
			WCHAR generated[32];
			_snwprintf_s(generated, COUNT_OF(generated), _TRUNCATE,
				L"Data%d", unnamed++);
			if (!JsonAppendEscapedXml(buffer, length, capacity, generated))
				ok = FALSE;
		}
		else {
			if (!JsonAppendEscapedXml(buffer, length, capacity, name))
				ok = FALSE;
		}

		if (ok && !JsonAppend(buffer, length, capacity, L":"))
			ok = FALSE;
		if (ok && !JsonAppendEscapedXml(buffer, length, capacity, value))
			ok = FALSE;

		free(value);
		if (name) free(name);
		if (!ok)
			break;

		p = valueEnd + wcslen(L"</Data>");
	}

	return ok;
}

static WCHAR* WinEventTimeToISO8601(ULONGLONG ulongTime)
{
	static WCHAR result[64];
	SYSTEMTIME sysTime;
	FILETIME fTime;
	ULARGE_INTEGER ulargeTime;

	ulargeTime.QuadPart = ulongTime;
	fTime.dwLowDateTime = ulargeTime.LowPart;
	fTime.dwHighDateTime = ulargeTime.HighPart;

	if (!FileTimeToSystemTime(&fTime, &sysTime)) {
		Log(LOG_ERROR | LOG_SYS, "Error formatting event time to ISO-8601");
		return NULL;
	}

	_snwprintf_s(result, COUNT_OF(result), _TRUNCATE,
		L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
		sysTime.wYear, sysTime.wMonth, sysTime.wDay,
		sysTime.wHour, sysTime.wMinute, sysTime.wSecond,
		sysTime.wMilliseconds);

	return result;
}

static WCHAR* BuildEventJson(EVT_HANDLE hEvent, PEVT_VARIANT eventInfo,
	const WCHAR* provider)
{
	WCHAR* json = NULL;
	size_t length = 0;
	size_t capacity = 0;
	WCHAR* timestamp = NULL;
	WCHAR* channel = NULL;
	WCHAR* computer = NULL;
	WCHAR* xml = NULL;
	DWORD bufferSize = 0;
	DWORD bufferUsed = 0;
	WCHAR tmp[64];
	ULONGLONG keyword;
	int eventId;
	int level;
	boolean ok = TRUE;

	/*
	 * Render the complete event as XML.  The first call is expected to
	 * fail with ERROR_INSUFFICIENT_BUFFER and tells us the required size.
	 */
	if (!EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL,
		&bufferUsed, NULL)) {
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			Log(LOG_WARNING | LOG_SYS, "EvtRender(EventXml) failed");
			return NULL;
		}
		bufferSize = bufferUsed;
	}

	if (bufferSize == 0)
		return NULL;

	xml = (WCHAR*)malloc(bufferSize);
	if (xml == NULL)
		return NULL;

	if (!EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, xml,
		&bufferUsed, NULL)) {
		free(xml);
		Log(LOG_WARNING | LOG_SYS, "EvtRender(EventXml) failed");
		return NULL;
	}

	timestamp = WinEventTimeToISO8601(eventInfo[1].FileTimeVal);
	channel = (eventInfo[5].Type == EvtVarTypeNull) ? L"" : eventInfo[5].StringVal;
	computer = (eventInfo[6].Type == EvtVarTypeNull) ? L"" : eventInfo[6].StringVal;
	keyword = (eventInfo[4].Type == EvtVarTypeNull) ? 0 : eventInfo[4].UInt64Val;
	eventId = (int)eventInfo[2].UInt16Val;
	level = (eventInfo[3].Type == EvtVarTypeNull) ? 0 : (int)eventInfo[3].ByteVal;

	ok = JsonAppend(&json, &length, &capacity, L"{\"timestamp\":");
	if (ok) ok = JsonAppendEscapedXml(&json, &length, &capacity,
		timestamp ? timestamp : L"");
	if (ok) ok = JsonAppend(&json, &length, &capacity, L",\"computer\":");
	if (ok) ok = JsonAppendEscapedXml(&json, &length, &capacity, computer);
	if (ok) ok = JsonAppend(&json, &length, &capacity, L",\"channel\":");
	if (ok) ok = JsonAppendEscapedXml(&json, &length, &capacity, channel);
	if (ok) ok = JsonAppend(&json, &length, &capacity, L",\"provider\":");
	if (ok) ok = JsonAppendEscapedXml(&json, &length, &capacity, provider);
	if (ok) ok = JsonAppend(&json, &length, &capacity, L",\"event_id\":");
	if (ok) ok = JsonAppendInt(&json, &length, &capacity, eventId);
	if (ok) ok = JsonAppend(&json, &length, &capacity, L",\"level\":");
	if (ok) ok = JsonAppendInt(&json, &length, &capacity, level);
	if (ok) ok = JsonAppend(&json, &length, &capacity, L",\"keywords\":\"0x");
	_snwprintf_s(tmp, COUNT_OF(tmp), _TRUNCATE, L"%llX",
		(unsigned long long)keyword);
	if (ok) ok = JsonAppend(&json, &length, &capacity, tmp);
	if (ok) ok = JsonAppend(&json, &length, &capacity, L"\",\"data\":{");
	if (ok) ok = JsonAppendEventData(&json, &length, &capacity, xml);
	if (ok) ok = JsonAppend(&json, &length, &capacity, L"}}");

	free(xml);

	if (!ok) {
		if (json) free(json);
		return NULL;
	}

	return json;
}

/* Get specific values from an event */
PEVT_VARIANT GetEventInfo(EVT_HANDLE hEvent)
{
	EVT_HANDLE hContext = NULL;
	PEVT_VARIANT pRenderedEvents = NULL;
	LPWSTR ppValues[] = {L"Event/System/Provider/@Name",
						 L"Event/System/TimeCreated/@SystemTime",
						 L"Event/System/EventID",
						 L"Event/System/Level",
						 L"Event/System/Keywords",
						 L"Event/System/Channel",
						 L"Event/System/Computer" };

    DWORD count = COUNT_OF(ppValues);
    DWORD dwReturned = 0;
	DWORD dwBufferSize = (256*sizeof(LPWSTR)*count);
	DWORD dwValuesCount = 0;
	DWORD status = 0;

	/* Create the context to use for EvtRender */
	hContext = EvtCreateRenderContext(count, (LPCWSTR*)ppValues, EvtRenderContextValues);
	if (NULL == hContext) {
		Log(LOG_ERROR|LOG_SYS, "EvtCreateRenderContext failed");
		goto cleanup;
	}

	pRenderedEvents = (PEVT_VARIANT)malloc(dwBufferSize);
	/* Use EvtRender to capture the Publisher name from the Event */
	/* Log Errors to the event log if things go wrong */
	if (!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedEvents, &dwReturned, &dwValuesCount)) {
		if (ERROR_INSUFFICIENT_BUFFER == GetLastError()) {
			dwBufferSize = dwReturned;
			realloc(pRenderedEvents, dwBufferSize);
			if (!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedEvents, &dwReturned, &dwValuesCount)) {
				if (LogInteractive)
					printf("Error Rendering Event");
				status = ERR_FAIL;
			}
		} else {
			status = ERR_FAIL;
			if (LogInteractive)
				printf("Error Rendering Event");
		}
	}

cleanup:
	if (hContext)
		EvtClose(hContext);

	if (status == ERR_FAIL)
		return NULL;
	else 
		return pRenderedEvents;
}

/* Gets the specified message string from the event. If the event does not
   contain the specified message, the function returns NULL. */
LPWSTR GetMessageString(EVT_HANDLE hMetadata, EVT_HANDLE hEvent)
{
	LPWSTR pBuffer = NULL;
	DWORD dwBufferSize = 0;
	DWORD dwBufferUsed = 0;
	DWORD status = 0;

	/* Get the message string from the provider */
	EvtFormatMessage(hMetadata, hEvent, 0, 0, NULL, EvtFormatMessageEvent, dwBufferSize, pBuffer, &dwBufferUsed);
    
	/* Ensure the call succeeded */
	/* If buffer was not large enough realloc it */
	status = GetLastError();
	if (ERROR_INSUFFICIENT_BUFFER == status) {
		dwBufferSize = dwBufferUsed;

		pBuffer = (LPWSTR)malloc(dwBufferSize * sizeof(WCHAR));

		/* Once we have realloc'd the buffer try to grab the message string again */
		if (pBuffer)
			EvtFormatMessage(hMetadata, hEvent, 0, 0, NULL, EvtFormatMessageEvent, dwBufferSize, pBuffer, &dwBufferUsed);
		else {
			Log(LOG_ERROR|LOG_SYS, "EvtFormatMessage: malloc failed");
			return NULL;
		}
	}
	else if (ERROR_EVT_MESSAGE_NOT_FOUND == status || ERROR_EVT_MESSAGE_ID_NOT_FOUND == status) {
		if (pBuffer)
			free(pBuffer);
		return NULL;
	}
	else {
		if (LogInteractive)
			printf("EvtFormatMessage failed : could not get message string\n");
		if (pBuffer)
			free(pBuffer);
		return NULL;
	}

	/* Success */
	return pBuffer;
}

/* Process a given event */
DWORD ProcessEvent(EVT_HANDLE hEvent, PVOID context)
{
    EVT_HANDLE hProviderMetadata = NULL;
	PEVT_VARIANT eventInfo = NULL;
    LPWSTR pwsMessage = NULL;
	LPWSTR pwszPublisherName = NULL;
	ULONGLONG eventTime;
	ULONGLONG keyword;
    DWORD status = ERROR_SUCCESS;
	int event_id = 0;
	int winlevel = 0;
	int level = 0;

	WCHAR source[SOURCE_SZ];
	WCHAR hostname[HOSTNAME_SZ];
	WCHAR * formatted_string = NULL;
	WCHAR * tstamp = NULL;
	WCHAR * index = NULL;
	WCHAR * eventJson = NULL;
	WCHAR defmsg[ERRMSG_SZ];
	WCHAR tstamped_message[SYSLOG_DEF_SZ];


    /* Get and store the publishers new Windows Events name */
	eventInfo = GetEventInfo(hEvent);
	if (!eventInfo) {
		return ERR_CONTINUE;
	}
	pwszPublisherName = (LPWSTR)eventInfo[0].StringVal;
	eventTime = eventInfo[1].FileTimeVal;
	event_id = eventInfo[2].UInt16Val;



	/* Check for the "Microsoft-Windows-" prefix in the publisher name */
	/* and remove it if found. Saves 18 characters in the message */
	if(wcsncmp(pwszPublisherName, L"Microsoft-Windows-", 18) == 0)
		wcsncpy_s(source, COUNT_OF(source), pwszPublisherName+18, _TRUNCATE);
	else
		wcsncpy_s(source, COUNT_OF(source), pwszPublisherName, _TRUNCATE);

	/* Check Event Info Against Ignore List */
	if (WIgnoreSyslogEvent(IgnoredEvents, source, event_id)) {
		return ERR_CONTINUE;
	}

	/* Format Event Timestamp */
	if ((tstamp = WinEventTimeToString(eventTime)) == NULL)
		tstamp = L"TIME_ERROR";

	/*
	 * JSON mode: keep the original filtering and severity calculation,
	 * but replace the human-readable event message with structured JSON.
	 */
	eventJson = BuildEventJson(hEvent, eventInfo, pwszPublisherName);
	if (eventJson == NULL) {
		free(eventInfo);
		if (hEvent)
			EvtClose(hEvent);
		return ERR_CONTINUE;
	}

	/* Add hostname for RFC compliance (RFC 3164) */
	if (ProgramUseIPAddress == TRUE) {
		_snwprintf_s(hostname, HOSTNAME_SZ, _TRUNCATE, L"%S", ProgramHostName);
	} else {
		if (ExpandEnvironmentStringsW(L"%COMPUTERNAME%", hostname, COUNT_OF(hostname)) == 0) {
			wcscpy_s(hostname, COUNT_OF(hostname), L"HOSTNAME_ERR");
			Log(LOG_ERROR|LOG_SYS, "Cannot expand %COMPUTERNAME%");
		}
    }

	/* replace every space in source by underscores */
	index = source;
	while( *index ) {
		if( *index == L' ' ) {
			*index = L'_';
		}
		index++;
	}

	/* Add Timestamp and hostname then format source & event ID for consistency with Event Viewer */
    if(SyslogIncludeTag)
    {
        _snwprintf_s(tstamped_message, COUNT_OF(tstamped_message), _TRUNCATE, L"%s %s %S: %s: %i: ",
            tstamp,
            hostname,
            SyslogTag,
            source,
            event_id
        );
    }
    else
    {
        _snwprintf_s(tstamped_message, COUNT_OF(tstamped_message), _TRUNCATE, L"%s %s %s: %i: ",
            tstamp,
            hostname,
            source,
            event_id
        );
    }

	/********************************************/
	/*         GENERATE EVENT MESSAGE           */
	/********************************************/
	if (context == NULL){
		winlevel = (int)eventInfo[3].ByteVal;
		/* Select syslog level */
		switch (winlevel) {
		case WINEVENT_CRITICAL_LEVEL:
			level = LOG_ERROR;
			break;
		case WINEVENT_ERROR_LEVEL:
			level = LOG_ERROR;
			break;
		case WINEVENT_WARNING_LEVEL:
			level = LOG_WARNING;
			break;
		default:
			level = LOG_INFO;
			break;
		}


		/* Get the handle to the provider's metadata that contains the message strings. */
		hProviderMetadata = EvtOpenPublisherMetadata(NULL, pwszPublisherName, NULL, 0, 0);
		if (NULL == hProviderMetadata) {
			if (LogInteractive)
				printf("%i:%S: OpenPublisherMetadata failed for Publisher: \"%S\"", event_id, source, source);
			return ERR_CONTINUE;
		}

		/* Get the message string from the event */
		pwsMessage = GetMessageString(hProviderMetadata, hEvent);
		if (pwsMessage == NULL) {
			
			Log(level | LOG_SYS, "%i:%S: Error getting message string for event DETAILS: Publisher: %S EventID: %i", event_id, source, source, event_id);

			EvtClose(hProviderMetadata);
			return ERR_CONTINUE;
		}
		

		/* Get string and strip whitespace */
		formatted_string = CollapseExpandMessageW(pwsMessage);

		/* Create a default message if resources or formatting didn't work */
		if (formatted_string == NULL) {
			if(SyslogIncludeTag)
			{
				_snwprintf_s(defmsg, COUNT_OF(defmsg), _TRUNCATE,
					L"%S: (Facility: %u, Status: %s)",
					SyslogTag,
					HRESULT_FACILITY(event_id),
					FAILED(event_id) ? L"Failure" : L"Success"
				);
			}
			else
			{
				_snwprintf_s(defmsg, COUNT_OF(defmsg), _TRUNCATE,
					L"(Facility: %u, Status: %s)",
					HRESULT_FACILITY(event_id),
					FAILED(event_id) ? L"Failure" : L"Success"
				);
			}
			formatted_string = defmsg;
		}
	}
	else {
		/*if (LogInteractive){
			Log(LOG_INFO, "Run login plugin");
		}*/
		formatted_string = pluginLogin(hEvent);

		/*if (LogInteractive) {
			Log(LOG_INFO, "Plugin returned: %ls", formatted_string);
		}*/
		if (formatted_string == NULL){
			if (eventInfo)
				free(eventInfo);

			if (hProviderMetadata)
				EvtClose(hProviderMetadata);
			if (hEvent)
				EvtClose(hEvent);
			
			return ERR_CONTINUE;
		}

	}


	/* Get Event Error Level. In the case of Security Events,
	 * set Failures to Error instead of notice using the
	 * keyword attribute
	 */
	keyword = (EvtVarTypeNull == eventInfo[4].Type) ? 0 : eventInfo[4].UInt64Val;
	if ((keyword & WINEVENT_KEYWORD_AUDIT_FAILURE) != 0) {
        // Add AUDIT_FAILURE message for better parsing
        wcsncat_s(tstamped_message, COUNT_OF(tstamped_message), L"AUDIT_FAILURE ", _TRUNCATE);
		winlevel = WINEVENT_ERROR_LEVEL;
    }
	else
		winlevel = (int)eventInfo[3].ByteVal;

	/* Select syslog level */
	switch (winlevel) {
		case WINEVENT_CRITICAL_LEVEL:
			level = SYSLOG_BUILD(SyslogFacility, SYSLOG_CRIT);
			break;		
		case WINEVENT_ERROR_LEVEL:
			level = SYSLOG_BUILD(SyslogFacility, SYSLOG_ERR);
			break;
		case WINEVENT_WARNING_LEVEL:
			level = SYSLOG_BUILD(SyslogFacility, SYSLOG_WARNING);
			break;
		case WINEVENT_INFORMATION_LEVEL:
			level = SYSLOG_BUILD(SyslogFacility, SYSLOG_NOTICE);
			break;
		case WINEVENT_AUDIT_LEVEL:
            wcsncat_s(tstamped_message, COUNT_OF(tstamped_message), L"AUDIT_SUCCESS ", _TRUNCATE);
			level = SYSLOG_BUILD(SyslogFacility, SYSLOG_NOTICE);
			break;
		case WINEVENT_VERBOSE_LEVEL:
			level = SYSLOG_BUILD(SyslogFacility, SYSLOG_DEBUG);
			break;

		/* Everything else */
		default:
			level = SYSLOG_BUILD(SyslogFacility, SYSLOG_NOTICE);
			break;
	}

	/* Combine the message strings */
	/* The JSON is the complete syslog MSG; do not append the legacy text. */
	_snwprintf_s(tstamped_message, COUNT_OF(tstamped_message), _TRUNCATE,
		L"%s", eventJson);

	/* Send the event to the Syslog Server */
	/* Making sure it is severe enough to be logged */

	if (SyslogLogLevel == 0 || (SyslogLogLevel >= (DWORD)winlevel && winlevel > 0))
		if (SyslogSendW(tstamped_message, level))
			status = ERR_FAIL;

	if (eventJson)
		free(eventJson);

	/* Cleanup memory and open handles */
	if(pwsMessage)
		free(pwsMessage);
	if(eventInfo)
		free(eventInfo);

	if (hProviderMetadata)
		EvtClose(hProviderMetadata);
	if (hEvent)
		EvtClose(hEvent);

	return status;
}

/* Format Timestamp from EventLog */
WCHAR * WinEventTimeToString(ULONGLONG ulongTime)
{
	SYSTEMTIME sysTime;
	FILETIME fTime, lfTime;
	ULARGE_INTEGER ulargeTime;
	struct tm tm_struct;
	WCHAR result[17] = L"";
	static WCHAR formatted_result[] = L"Mmm dd hh:mm:ss";

	memset(&tm_struct, 0, sizeof(tm_struct));

	/* Convert from ULONGLONG to usable FILETIME value */
	ulargeTime.QuadPart = ulongTime;
	
	fTime.dwLowDateTime = ulargeTime.LowPart;
	fTime.dwHighDateTime = ulargeTime.HighPart;

	/* Adjust time value to reflect current timezone */
	/* then convert to a SYSTEMTIME */
	if (FileTimeToLocalFileTime(&fTime, &lfTime) == 0) {
		Log(LOG_ERROR|LOG_SYS,"Error formatting event time to local time");
		return NULL;
	}
	if (FileTimeToSystemTime(&lfTime, &sysTime) == 0) {
		Log(LOG_ERROR|LOG_SYS,"Error formatting event time to system time");
		return NULL;
	}

	/* Convert SYSTEMTIME to tm */
	tm_struct.tm_year = sysTime.wYear - 1900;
	tm_struct.tm_mon  = sysTime.wMonth - 1;
	tm_struct.tm_mday = sysTime.wDay;
	tm_struct.tm_hour = sysTime.wHour;
	tm_struct.tm_wday = sysTime.wDayOfWeek;
	tm_struct.tm_min  = sysTime.wMinute;
	tm_struct.tm_sec  = sysTime.wSecond;
	
	/* Format timestamp string */
	wcsftime(result, COUNT_OF(result), L"%b %d %H:%M:%S", &tm_struct);
	if (result[4] == L'0') /* Replace leading zero with a space for */
		result[4] = L' ';  /* single digit days so we comply with the RFC */

	wcsncpy_s(formatted_result, COUNT_OF(L"Mmm dd hh:mm:ss"), result, _TRUNCATE);
	
	return formatted_result;
}