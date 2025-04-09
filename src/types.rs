#[derive(Debug)]
pub struct PppSessionInfo {
    pub ip: [u8; 4],
    pub dns1: Option<[u8; 4]>,
    pub dns2: Option<[u8; 4]>,
}

#[derive(Debug)]
pub enum PppState {
    DhcpSendInfo,
    WaitEchoRequest,
    SendLcpRequest,
    WaitLcpRequest,
    WaitLcpReject,
    SendPapAuth,
    WaitPapAck,
    SendIpcpRequest,
    WaitIpcpRequest,
    Done,
    WaitIpcpNakWithOffer,
    WaitIpcpReject,
    WaitIpcpFinalAck,
    WaitLcpAck,
    WaitLcpNak,
    WaitDhcpAck,
    Error(String),
}