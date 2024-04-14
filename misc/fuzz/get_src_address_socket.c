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
	if(Size < 1) {
		return 0;
	}

	sip_msg_t msg;
	memset(&msg, 0, sizeof(sip_msg_t));

	msg.buf = (char *)malloc(Size + 1);
	if(!msg.buf) {
		return 0;
	}

	memcpy(msg.buf, Data, Size);
	msg.buf[Size] = '\0';
	msg.len = Size;

	str src_socket;
	int result = get_src_address_socket(&msg, &src_socket);

	if(src_socket.s) {
		free(src_socket.s);
	}

	free(msg.buf);

	return 0;
}