| property_id | protocol | section_id | normative_level | MITL_formula |
| --- | --- | --- | --- | --- |
| sip.invite.response_within_timer_b | SIP | RFC3261 §17.1.1.1-§17.1.1.2 | MUST + default binding | `G(invite -> F[0,32000] invite_rsp)` |
| sip.invite.no_retransmit_before_timer_a | SIP | RFC3261 §17.1.1.2 | MUST + default binding | `G(invite -> G[0,499] (!rtx))` |
| sip.invite.no_second_retransmit_before_doubled_timer_a | SIP | RFC3261 §17.1.1.2 | MUST | `G(rtx1 -> G[0,999] (!rtx2))` |
| dtls.clienthello.no_retransmit_before_initial_rto | DTLS | RFC6347 §4.2.4.1 | SHOULD | `G(ch -> G[0,999] (!rtx))` |
| dtls.clienthello.no_second_retransmit_before_doubled_rto | DTLS | RFC6347 §4.2.4.1 | SHOULD | `G(rtx1 -> G[0,1999] (!rtx2))` |
| ssh.login_grace_disconnect_or_auth | SSH | sshd_config LoginGraceTime | official default implementation behavior | `G(conn_open -> F[0,120000] auth_done)` |
| rtsp.session_activity_before_default_timeout | RTSP | RFC2326 §12.37 + Appendix A | default timeout semantics | `G(session_open -> F[0,60000] session_activity)` |
| dicom.acse_response_within_default_timeout | DICOM | dcmqrscp other network options | official default implementation option | `G(assoc_req -> F[0,30000] acse_rsp)` |
| smtp.mail.reply_within_minimum_timeout | SMTP | RFC5321 §4.5.3.2.3 | SHOULD | `G(mail -> F[0,300000] mail_rsp)` |
