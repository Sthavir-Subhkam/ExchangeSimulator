# NSE FO Trimmed NNF Protocol 9.48 Context

Source PDF:

- `/home/sthavir/ExchangeSimulator/TP_FO_Trimmed_NNF_PROTOCOL_9.48_20260313174413.pdf`
- Title: `Protocol For Non-NEAT Front End (NNF)`
- Version/source timestamp visible in filename: `20260313174413`
- PDF metadata creation/modification date: `2026-03-13 14:58:17 IST`
- Pages: `313`

This note caches the transaction-code findings used while auditing
`include/nse_fo_exchange_sim/protocol.h`, so future work can avoid re-parsing
the PDF for the same constants.

## Login, Gateway, And Session Codes

| Name | Code | Notes |
| --- | ---: | --- |
| `SYSTEM_INFORMATION_IN` | `1600` | System information request |
| `SYSTEM_INFORMATION_OUT` | `1601` | System information response |
| `SIGN_ON_REQUEST_IN` | `2300` | User sign-on/logon request |
| `SIGN_ON_REQUEST_OUT` | `2301` | User sign-on/logon response |
| `GR_REQUEST` | `2400` | Gateway router request |
| `GR_RESPONSE` | `2401` | Gateway router response |
| `DOWNLOAD_REQUEST` | `7000` | Message download request |
| `TRAILER_RECORD` | `7031` | Message download trailer |
| `UPDATE_LOCALDB_IN` | `7300` | Update local database request |
| `UPDATE_LOCALDB_TRAILER` | `7308` | Update local database trailer |
| `BOX_SIGN_ON_REQUEST_IN` | `23000` | Box sign-on request |
| `BOX_SIGN_ON_REQUEST_OUT` | `23001` | Box sign-on response |
| `SECURE_BOX_REGISTRATION_REQUEST_IN` | `23008` | Secure box registration request |
| `SECURE_BOX_REGISTRATION_RESPONSE_OUT` | `23009` | Secure box registration response |
| Heartbeat | `23506` | Heartbeat transaction code |

## Price/Volume Modification Codes

| Name | Code | Structure | Notes |
| --- | ---: | --- | --- |
| `PRICE_MOD_IN` | `2013` | `PRICE_MOD` | Price/volume modification request |
| `PRICE_MOD_ACK_IN` | `20406` | `PRICE_MOD` | Immediate ack request code |
| `QUICK_ACK_PM_RESP` | `20407` | `MS_ACK_RESPONSE` | Quick ack response code |

## Trimmed Order Request Codes

| Name | Code | Structure | Size | Notes |
| --- | ---: | --- | ---: | --- |
| `BOARD_LOT_IN_TR` | `20000` | `MS_OE_REQUEST_TR` | `158` | Trimmed order entry request |
| `TRIMMED_BOARD_LOT_ACK_IN` | `20400` | `MS_OE_REQUEST_TR` | `158` | Immediate ack request code |
| `ORDER_MOD_IN_TR` | `20040` | `MS_OM_REQUEST_TR` | `186` | Trimmed order modification request |
| `TRIMMED_ORDER_MOD_ACK_IN` | `20402` | `MS_OM_REQUEST_TR` | `186` | Immediate ack request code |
| `ORDER_CANCEL_IN_TR` | `20070` | `MS_OM_REQUEST_TR` | `186` | Trimmed order cancellation request |
| `TRIMMED_ORDER_CANCEL_ACK_IN` | `20404` | `MS_OM_REQUEST_TR` | `186` | Immediate ack request code |
| `ORDER_QUICK_CANCEL_IN_TR` | `20060` | `MS_OM_REQUEST_TR` | `186` | Trimmed quick cancel request |

## Quick Ack Response Codes

All of these use `MS_ACK_RESPONSE`, packet length `22`.

| Name | Code |
| --- | ---: |
| `QUICK_ACK_OE_RESP` | `20401` |
| `QUICK_ACK_OM_RESP` | `20403` |
| `QUICK_ACK_OC_RESP` | `20405` |
| `QUICK_ACK_PM_RESP` | `20407` |

## Trimmed Final Order/Trade Response Codes

| Name | Code | Structure | Size | Notes |
| --- | ---: | --- | ---: | --- |
| `ORDER_CONFIRMATION_TR` | `20073` | `MS_OE_RESPONSE_TR` | `240` | Order entry final confirmation |
| `ORDER_MOD_CONFIRMATION_TR` | `20074` | `MS_OE_RESPONSE_TR` | `240` | Order modification final confirmation |
| `ORDER_CXL_CONFIRMATION_TR` | `20075` | `MS_OE_RESPONSE_TR` | `240` | Order cancellation final confirmation |
| `TRADE_CONFIRMATION_TR` | `20222` | `MS_TRADE_CONFIRM_TR` | `230` | Trimmed trade confirmation |

## Non-Trimmed Codes That Are Easy To Confuse

These are present in the same PDF but are not the trimmed order request codes.

| Name | Code | Structure | Size | Notes |
| --- | ---: | --- | ---: | --- |
| `BOARD_LOT_IN` | `2000` | `MS_OE_REQUEST` | `316` | Non-trimmed order entry request |
| `ORDER_MOD_IN` | `2040` | `MS_OE_REQUEST` | `316` | Non-trimmed order modification request |
| `ORDER_CANCEL_IN` | `2070` | `MS_OE_REQUEST` | `316` | Non-trimmed order cancellation request |
| `ORDER_CONFIRMATION` | `2073` | `MS_OE_REQUEST` | `316` | Non-trimmed order confirmation |
| `ORDER_MOD_CONFIRMATION` | `2074` | `MS_OE_REQUEST` | `316` | Non-trimmed modification confirmation |
| `ORDER_CANCEL_CONFIRMATION` | `2075` | `MS_OE_REQUEST` | `316` | Non-trimmed cancellation confirmation |
| `TRADE_CONFIRMATION` | `2222` | `MS_TRADE_CONFIRM` | `234` | Non-trimmed trade confirmation |

## Reject/Error Codes

The PDF lists these reject/error transaction codes in the non-trimmed tables,
and the trimmed order response section does not introduce separate
`200xx` reject/error codes.

| Name | Code | Structure | Notes |
| --- | ---: | --- | --- |
| `ORDER_MOD_REJECT` | `2042` | `MS_OE_REQUEST` | Modification reject/error |
| `ORDER_CANCEL_REJECT` | `2072` | `MS_OE_REQUEST` | Cancellation reject/error |
| `ORDER_ERROR` | `2231` | `MS_OE_REQUEST` | Order entry reject/error |

## Protocol Header Mapping

The intended `protocol.h` mapping after the audit is:

| Header constant | Code |
| --- | ---: |
| `kTxnPriceVolModification` | `2013` |
| `kTxnPriceVolModificationAck` | `20406` |
| `kTxnQuickAckPriceVolModificationResponse` | `20407` |
| `kTxnOrderEntryRequestTrimmed` | `20000` |
| `kTxnOrderEntryAckTrimmed` | `20400` |
| `kTxnOrderModificationRequestTrimmed` | `20040` |
| `kTxnOrderModificationAckTrimmed` | `20402` |
| `kTxnOrderCancellationRequestTrimmed` | `20070` |
| `kTxnOrderCancellationAckTrimmed` | `20404` |
| `kTxnOrderConfirmationTrimmed` | `20073` |
| `kTxnOrderModificationConfirmationTrimmed` | `20074` |
| `kTxnOrderCancellationConfirmationTrimmed` | `20075` |
| `kTxnTradeConfirmationTrimmed` | `20222` |
| `kTxnQuickAckOrderEntryResponse` | `20401` |
| `kTxnQuickAckOrderModificationResponse` | `20403` |
| `kTxnQuickAckOrderCancellationResponse` | `20405` |
| `kTxnOrderErrorTrimmed` | `2231` |
| `kTxnOrderModificationErrorTrimmed` | `2042` |
| `kTxnOrderCancellationErrorTrimmed` | `2072` |

Compatibility aliases:

- `kTxnOrderEntryTrimmed == kTxnOrderEntryRequestTrimmed`
- `kTxnOrderModificationTrimmed == kTxnOrderModificationRequestTrimmed`
- `kTxnOrderCancellationTrimmed == kTxnOrderCancellationRequestTrimmed`
