# Protocol status

The server implements the Play Online services used by `boz.s3e`.

| Transport | Port | Traffic |
| --- | ---: | --- |
| TCP | 3074 | login, matchmaking, room updates and peer signaling |
| UDP | 3478 | public endpoint discovery |
| UDP between players | chosen by the game | gameplay and voice chat |

Working:

- account creation and login
- Single Map room creation and search
- Map Vote room creation and search
- joining and leaving rooms
- concurrent rooms
- host/client signaling

Not yet working or verified:

- play between devices on separate Internet connections
