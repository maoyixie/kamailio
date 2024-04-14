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
	// Create a sip_msg struct to pass to parse_privacy
	struct sip_msg msg;

	// Initialize the sip_msg struct with the fuzzer data
	if(Size > 0) {
		msg.buf = (char *)malloc(Size + 1);

		if(!msg.buf) {
			return 0;
		}

		memcpy(msg.buf, Data, Size);
		msg.buf[Size] = '\0';
		msg.len = Size;
	} else {
		// If there is no input, set the sip_msg to empty values
		msg.buf = "";
		msg.len = 0;
	}

	// Call the target function with the fuzzed data
	int result = parse_privacy(&msg);

	// Free the dynamically allocated memory
	if(Size > 0) {
		free(msg.buf);
	}

	// To avoid compiler optimization, we use this return statement. But for fuzzing, the return value is not used.
	return 0;
}