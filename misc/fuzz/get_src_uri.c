#include "../config.h"
#include "../parser/sdp/sdp.h"
#include "../parser/parse_uri.c"
#include "../parser/parse_hname2.h"
#include "../parser/contact/parse_contact.h"
#include "../parser/parse_from.h"
#include "../parser/parse_to.h"
#include "../parser/parse_rr.h"
#include "../parser/parse_refer_to.h"
#include "../parser/parse_ppi_pai.h"
#include "../parser/parse_privacy.h"
#include "../parser/parse_diversion.h"
#include "../parser/parse_identityinfo.h"
#include "../parser/parse_disposition.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	sip_msg_t msg;
	str uri;
	int tmode;

	if(Size < sizeof(int) + sizeof(tmode)) {
		return 0;
	}

	// Copy tmode from input data
	memcpy(&tmode, Data, sizeof(tmode));
	Data += sizeof(tmode);
	Size -= sizeof(tmode);

	// Initialize sip_msg_t structure
	msg.buf = (char *)Data;
	msg.len = Size;

	// Call the target function
	int result = get_src_uri(&msg, tmode, &uri);

	// Perform cleanup if necessary
	if(uri.s != NULL) {
		free(uri.s);
	}

	return 0;
}