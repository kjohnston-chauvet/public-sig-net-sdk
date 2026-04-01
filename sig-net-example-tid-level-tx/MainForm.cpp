//==============================================================================
// Sig-Net Protocol Framework - Transmitter Application Implementation
//==============================================================================
//
// Copyright (c) 2026 Singularity (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//==============================================================================
// Author:       Wayne Howell
// Date:         March 28, 2026
// Prot Version: v0.12
// Description:  Implementation of Sig-Net TIDLevel transmitter main form.
//               Handles K0 validation, key derivation, DMX pattern generation,
//               packet building, hex dump display, and UDP transmission.
//==============================================================================

//---------------------------------------------------------------------------

#include <vcl.h>
#pragma hdrstop

#include "MainForm.h"
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.dfm"
TFormSigNetTest *FormSigNetTest;

static void SetLabelsTransparentRecursive(TWinControl* root)
{
    if (!root) {
        return;
    }

    for (int i = 0; i < root->ControlCount; i++) {
        TControl* ctrl = root->Controls[i];
        TLabel* lbl = dynamic_cast<TLabel*>(ctrl);
        if (lbl) {
            lbl->Transparent = true;
        }

        TWinControl* child = dynamic_cast<TWinControl*>(ctrl);
        if (child) {
            SetLabelsTransparentRecursive(child);
        }
    }
}

//---------------------------------------------------------------------------
__fastcall TFormSigNetTest::TFormSigNetTest(TComponent* Owner)
    : TForm(Owner)
{
    keys_valid = false;
    k0_set = false;
    dmx_slot_count = 512;
    endpoint = 1;
    session_id = 1;
    sequence_num = 1;
    message_id = 1;
    send_count = 0;
    error_count = 0;
    last_packet_size = 0;
    udp_socket = INVALID_SOCKET;
    socket_initialized = false;
    rgb_r = 255;
    rgb_g = 0;
    rgb_b = 0;
    rgb_phase = 0;
    
    memset(k0_key, 0, sizeof(k0_key));
    memset(sender_key, 0, sizeof(sender_key));
    memset(citizen_key, 0, sizeof(citizen_key));
    memset(dmx_buffer, 0, sizeof(dmx_buffer));
    memset(tuid, 0, sizeof(tuid));
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTest::FormCreate(TObject *Sender)
{
    Caption = "Sig-Net Example [TIDLevel Sender]   Copyright Singularity (UK) Ltd  V0.2";

    // Initialize K0 display controls (read-only - populated by K0 entry dialog)
    EditK0->ReadOnly = true;
    EditK0->Text = "";
    EditSenderKey->ReadOnly = true;
    EditSenderKey->Text = "";
    EditCitizenKey->ReadOnly = true;
    EditCitizenKey->Text = "";

    // Initialize NIC selection - default to loopback
    selected_nic_ip = "127.0.0.1";
    EditNicIP->Text = "127.0.0.1";
    EditNicIP->ReadOnly = true;

    EditAnnounceVersionNum->Text = "1";
    EditAnnounceVersionString->Text = "v0.12-test";
        EditAnnounceMfgCode->Text = "0x534C";
    EditAnnounceProductVariant->Text = "0001";
    
    // Initialize device parameters
    EditTUID->Text = SigNet::TEST_TUID;
    SpinEndpoint->MinValue = 1;
    SpinEndpoint->Value = 1;
    SpinUniverse->MinValue = SigNet::MIN_UNIVERSE;
    SpinUniverse->MaxValue = SigNet::MAX_UNIVERSE;
    SpinUniverse->Value = 1;
    
    EditSessionID->Text = "1";
    EditSessionID->ReadOnly = true;
    EditSequence->Text = "1";
    EditSequence->ReadOnly = true;
    EditMessageID->Text = "1";
    EditMessageID->ReadOnly = true;

    ComboBoxDmxMode->ItemIndex = 0;  // Manual
    
    // Initialize auto-send timer (44 Hz = ~22.7 ms interval)
    TimerKeepAlive->Interval = 900;  // milliseconds
    TimerKeepAlive->Enabled = false;
    
    // Initialize DMX buffer to zero
    memset(dmx_buffer, 0, sizeof(dmx_buffer));
    
    // Create DMX fader controls (trackbars and labels)
    dmx_scroll_position = 0;
    for (int i = 0; i < 32; i++) {
        dmx_trackbars[i] = 0;
        dmx_labels[i] = 0;
    }
    CreateDMXFaderControls();
    PanelTrackbars->OnResize = PanelTrackbarsResize;
    SetLabelsTransparentRecursive(this);

    TimerHeartBeat->Enabled = false;
    TimerHeartBeat->Interval = 10;

    // K0-dependent controls start disabled until key derivation succeeds.
    UpdateK0DependentControls();
    
    // Initialize Winsock
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        LogError(String().sprintf(L"WSAStartup failed: %d", result));
        socket_initialized = false;
    } else {
        // Create UDP socket
        udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udp_socket == INVALID_SOCKET) {
            LogError(String().sprintf(L"Socket creation failed: %d", WSAGetLastError()));
            socket_initialized = false;
            WSACleanup();
        } else {
            // Bind socket to any local address (required for multicast)
            sockaddr_in local_addr;
            memset(&local_addr, 0, sizeof(local_addr));
            local_addr.sin_family = AF_INET;
            local_addr.sin_addr.s_addr = INADDR_ANY;
            local_addr.sin_port = 0;  // Let OS choose port
            
            if (bind(udp_socket, (sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
                LogError(String().sprintf(L"Socket bind failed: %d", WSAGetLastError()));
                closesocket(udp_socket);
                WSACleanup();
                socket_initialized = false;
            } else {
                // Set socket to allow multicast
                char loopback = 1;  // Enable loopback for local testing
                if (setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback, sizeof(loopback)) == SOCKET_ERROR) {
                    LogError(String().sprintf(L"Set loopback failed: %d", WSAGetLastError()));
                }
                
                unsigned char ttl = 16;  // Set TTL for multicast packets
                if (setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_TTL, (char*)&ttl, sizeof(ttl)) == SOCKET_ERROR) {
                    LogError(String().sprintf(L"Set TTL failed: %d", WSAGetLastError()));
                }
                
                // Allow broadcast (helps with some network configurations)
                int broadcast = 1;
                setsockopt(udp_socket, SOL_SOCKET, SO_BROADCAST, (char*)&broadcast, sizeof(broadcast));
                
                socket_initialized = true;
                LogMessage("UDP socket initialized and bound successfully.");
            }
        }
    }
    
    LogMessage("Sig-Net Test Application initialized.");
    LogMessage("Click 'Select K0...' to configure the root key.");
    LogMessage("Announce packets are manual: use the Announce button.");
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTest::FormDestroy(TObject *Sender)
{
    // Cleanup socket
    if (udp_socket != INVALID_SOCKET) {
        closesocket(udp_socket);
        udp_socket = INVALID_SOCKET;
    }
    
    if (socket_initialized) {
        WSACleanup();
        socket_initialized = false;
        LogMessage("UDP socket closed.");
    }
}
//---------------------------------------------------------------------------
void __fastcall TFormSigNetTest::ButtonSelectK0Click(TObject *Sender)
{
    // Parse TUID from UI so dialog can derive Manager Local key
    if (!ParseTUIDFromHex(EditTUID->Text)) {
        LogError("Invalid TUID - cannot open K0 dialog");
        return;
    }
    
    // Open K0 entry dialog
    TK0EntryDialog *dialog = new TK0EntryDialog(this);
    dialog->SetTUID(tuid);
    
    try {
        if (dialog->ShowModal() == mrOk) {
            // Get K0 from dialog
            dialog->GetK0(k0_key);
            
            // Derive keys required by this test application
            int32_t result = SigNet::Crypto::DeriveSenderKey(k0_key, sender_key);
            if (result != SigNet::SIGNET_SUCCESS) {
                LogError(String().sprintf(L"Failed to derive sender key: error %d", result));
                keys_valid = false;
                k0_set = false;
                UpdateK0DependentControls();
                return;
            }

            result = SigNet::Crypto::DeriveCitizenKey(k0_key, citizen_key);
            if (result != SigNet::SIGNET_SUCCESS) {
                LogError(String().sprintf(L"Failed to derive citizen key: error %d", result));
                keys_valid = false;
                k0_set = false;
                UpdateK0DependentControls();
                return;
            }
            
            // Display K0 and derived keys (Ks + Kc)
            char hex_buffer[65];
            hex_buffer[64] = '\0';
            
            for (int i = 0; i < 32; i++) {
                sprintf(hex_buffer + (i * 2), "%02X", k0_key[i]);
            }
            EditK0->Text = String(hex_buffer);
            
            for (int i = 0; i < 32; i++) {
                sprintf(hex_buffer + (i * 2), "%02X", sender_key[i]);
            }
            EditSenderKey->Text = String(hex_buffer);

            for (int i = 0; i < 32; i++) {
                sprintf(hex_buffer + (i * 2), "%02X", citizen_key[i]);
            }
            EditCitizenKey->Text = String(hex_buffer);
            
            keys_valid = true;
            k0_set = true;
            UpdateK0DependentControls();
            LogMessage("K0 selected and Ks/Kc derived successfully.");
            LogMessage("Ready to transmit TID_LEVEL and Announce packets.");
        } else {
            LogMessage("K0 selection cancelled.");
        }
    }
    __finally {
        delete dialog;
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTest::ButtonSendLevelPacketClick(TObject *Sender)
{
    if (SendPacket()) {
        LogMessage(String().sprintf(L"Packet sent: seq=%u, size=%u bytes", 
                   sequence_num - 1, last_packet_size));
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTest::ButtonSendAnnounceClick(TObject *Sender)
{
    if (SendAnnouncePacket()) {
        LogMessage(String().sprintf(L"Announce packet sent: seq=%u, size=%u bytes",
                   sequence_num - 1, last_packet_size));
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTest::ComboBoxDmxModeChange(TObject *Sender)
{
    bool is_dynamic = (ComboBoxDmxMode->ItemIndex == 1);
    TimerHeartBeat->Enabled = is_dynamic;
    if (is_dynamic) {
        LogMessage("DMX mode: Dynamic");
    } else {
        LogMessage("DMX mode: Manual");
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTest::CheckKeepAliveClick(TObject *Sender)
{
    // Only arm if K0 has been set
    if (CheckKeepAlive->Checked && k0_set) {
        TimerKeepAlive->Enabled = true;
        LogMessage("Keep-Alive enabled (900 ms)");
    } else {
        TimerKeepAlive->Enabled = false;
        LogMessage("Keep-Alive disabled");
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTest::TimerKeepAliveTimer(TObject *Sender)
{
    // Timer fired — no level packet sent in the last 900 ms; send keep-alive
    if (k0_set) {
        SendPacket();
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTest::TimerHeartBeatTimer(TObject *Sender)
{
    if (ComboBoxDmxMode->ItemIndex != 1) {
        return;
    }

    // Cycle RGB: R->G, G->B, B->R
    if (rgb_phase == 0) {
        if (rgb_r > 0) rgb_r--;
        if (rgb_g < 255) rgb_g++;
        if (rgb_r == 0 && rgb_g == 255) rgb_phase = 1;
    } else if (rgb_phase == 1) {
        if (rgb_g > 0) rgb_g--;
        if (rgb_b < 255) rgb_b++;
        if (rgb_g == 0 && rgb_b == 255) rgb_phase = 2;
    } else {
        if (rgb_b > 0) rgb_b--;
        if (rgb_r < 255) rgb_r++;
        if (rgb_b == 0 && rgb_r == 255) rgb_phase = 0;
    }

    // Fill DMX buffer: 1,4,7...=R 2,5,8...=G 3,6,9...=B
    for (int i = 0; i < 512; i++) {
        int slot = i % 3;
        if (slot == 0) {
            dmx_buffer[i] = rgb_r;
        } else if (slot == 1) {
            dmx_buffer[i] = rgb_g;
        } else {
            dmx_buffer[i] = rgb_b;
        }
    }

    SyncTrackbarsFromBuffer();
    SendPacket();
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTest::ButtonSelfTestClick(TObject *Sender)
{
    TSelfTestResultsForm* form = new TSelfTestResultsForm(Application);
    form->ShowModal();
    delete form;
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTest::ButtonSelectNicClick(TObject *Sender)
{
    TNicSelectDialog* dlg = new TNicSelectDialog(Application);
    dlg->SetCurrentIP(selected_nic_ip);
    try {
        if (dlg->ShowModal() == mrOk) {
            selected_nic_ip = dlg->GetSelectedIP();
            EditNicIP->Text = String(selected_nic_ip.c_str());
            LogMessage("Sender interface set to: " + String(selected_nic_ip.c_str()));
        }
    }
    __finally {
        delete dlg;
    }
}
//---------------------------------------------------------------------------

// Send a SigNet packet
bool TFormSigNetTest::SendPacket()
{
    if (!keys_valid) {
        LogError("Cannot send - keys not derived. Click Select K0 and complete key setup.");
        error_count++;
        return false;
    }
    
    // Parse TUID from UI
    if (!ParseTUIDFromHex(EditTUID->Text.Trim())) {
        LogError("Invalid TUID - must be 12 hex characters");
        error_count++;
        return false;
    }
    
    // Get parameters from UI
    uint16_t universe = SpinUniverse->Value;
    uint16_t endpoint_val = static_cast<uint16_t>(SpinEndpoint->Value);
    if (endpoint_val < 1) {
        endpoint_val = 1;
        SpinEndpoint->Value = 1;
        LogMessage("Endpoint adjusted to 1 (minimum allowed).");
    }
    
    // Build packet
    SigNet::PacketBuffer buffer;
    int32_t result = SigNet::BuildDMXPacket(
        buffer,
        universe,
        dmx_buffer,
        dmx_slot_count,
        tuid,
        endpoint_val,
        0x0000,  // mfg_code (standard messages)
        session_id,
        sequence_num,
        sender_key,
        message_id
    );
    
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"Failed to build packet: error %d", result));
        error_count++;
        return false;
    }
    
    last_packet_size = buffer.GetSize();
    
    // Calculate multicast address
    char multicast_ip[32];  // Larger buffer for safety
    memset(multicast_ip, 0, sizeof(multicast_ip));
    SigNet::CalculateMulticastAddress(universe, multicast_ip);

    bool transmit_success = true;
    
    // Send via Winsock UDP multicast
    if (socket_initialized && udp_socket != INVALID_SOCKET) {
        // Set multicast source interface only for explicit non-loopback selection.
        if (selected_nic_ip != "127.0.0.1") {
            struct in_addr iface_addr;
            iface_addr.s_addr = inet_addr(selected_nic_ip.c_str());
            if (iface_addr.s_addr == INADDR_NONE) {
                LogError("Invalid selected NIC IP; using OS default multicast interface.");
            } else {
                if (setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_IF,
                               (char*)&iface_addr, sizeof(iface_addr)) == SOCKET_ERROR) {
                    int if_err = WSAGetLastError();
                    LogError(String().sprintf(L"IP_MULTICAST_IF failed: WSA error %d; using OS default interface", if_err));
                }
            }
        }

        sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(SigNet::SIGNET_UDP_PORT);
        dest_addr.sin_addr.s_addr = inet_addr(multicast_ip);
        
        int bytes_sent = sendto(
            udp_socket,
            (const char*)buffer.GetBuffer(),
            buffer.GetSize(),
            0,
            (sockaddr*)&dest_addr,
            sizeof(dest_addr)
        );
        
        if (bytes_sent == SOCKET_ERROR) {
            int err = WSAGetLastError();
            // Retry once using default interface if a selected NIC route fails.
            if (selected_nic_ip != "127.0.0.1") {
                struct in_addr any_addr;
                any_addr.s_addr = INADDR_ANY;
                setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_IF,
                           (char*)&any_addr, sizeof(any_addr));

                bytes_sent = sendto(
                    udp_socket,
                    (const char*)buffer.GetBuffer(),
                    buffer.GetSize(),
                    0,
                    (sockaddr*)&dest_addr,
                    sizeof(dest_addr)
                );
                if (bytes_sent != SOCKET_ERROR) {
                    LogMessage("sendto() retry succeeded using default multicast interface.");
                }
            }

            if (bytes_sent == SOCKET_ERROR) {
                err = WSAGetLastError();
                LogError(String().sprintf(L"sendto() failed: WSA error %d", err));
                error_count++;
                transmit_success = false;
            }
        } else if (bytes_sent != buffer.GetSize()) {
            LogError(String().sprintf(L"Partial send: %d of %d bytes", bytes_sent, buffer.GetSize()));
            error_count++;
            transmit_success = false;
        }
    } else {
        if (send_count == 0) {
            LogError("Socket not initialized - cannot send packets");
        }
        error_count++;
        transmit_success = false;
    }
    
    if (!transmit_success) {
        return false;
    }
    
    // Increment counters
    send_count++;
    sequence_num = SigNet::IncrementSequence(sequence_num);
    message_id++;
    
    // Check for session rollover
    if (SigNet::ShouldIncrementSession(sequence_num)) {
        session_id++;
        sequence_num = 1;
        LogMessage(String().sprintf(L"Session rolled over to %u", session_id));
    }
    
    // Update UI
    EditSequence->Text = String().sprintf(L"%u", sequence_num);
    EditMessageID->Text = String().sprintf(L"%u", message_id);
    EditSessionID->Text = String().sprintf(L"%u", session_id);
    
    // Reset keep-alive timer: any successful send pushes it back to 900 ms
    if (k0_set && CheckKeepAlive->Checked) {
        TimerKeepAlive->Enabled = false;
        TimerKeepAlive->Enabled = true;
    }

    return true;
}
//---------------------------------------------------------------------------

bool TFormSigNetTest::SendAnnouncePacket()
{
    if (!keys_valid) {
        LogError("Cannot send announce - Kc not available. Click Select K0 first.");
        error_count++;
        return false;
    }

    if (!ParseTUIDFromHex(EditTUID->Text.Trim())) {
        LogError("Invalid TUID - must be 12 hex characters");
        error_count++;
        return false;
    }

    uint16_t firmware_version_id = 0;
    uint16_t mfg_code = 0;
    uint16_t product_variant_id = 0;

    try {
        firmware_version_id = static_cast<uint16_t>(StrToInt(EditAnnounceVersionNum->Text.Trim()));
    }
    catch (...) {
        LogError("Announce version number must be a valid 16-bit decimal value");
        error_count++;
        return false;
    }

    try {
        String mfg_code_text = EditAnnounceMfgCode->Text.Trim().UpperCase();
        if (mfg_code_text.Pos("0X") != 1) {
            mfg_code_text = "0x" + mfg_code_text;
        }
        mfg_code = static_cast<uint16_t>(StrToInt(mfg_code_text));
    }
    catch (...) {
        LogError("Manufacturer code must be valid hex (e.g. 534C or 0x534C)");
        error_count++;
        return false;
    }

    try {
        product_variant_id = static_cast<uint16_t>(StrToInt("0x" + EditAnnounceProductVariant->Text.Trim()));
    }
    catch (...) {
        LogError("Product variant ID must be valid hex (e.g. 0001)");
        error_count++;
        return false;
    }

    String fw_text = EditAnnounceVersionString->Text.Trim();
    if (fw_text.IsEmpty()) {
        LogError("Version string cannot be empty");
        error_count++;
        return false;
    }

    AnsiString fw_ansi = AnsiString(fw_text);

    // Protocol major is v1 in current implementation.
    const uint8_t protocol_version = 0x01;
    // Test sender app advertises Sender role.
    const uint8_t role_capability_bits = 0x02;
    const uint16_t change_count = 0x0000;

    SigNet::PacketBuffer buffer;
    int32_t result = SigNet::BuildAnnouncePacket(
        buffer,
        tuid,
        mfg_code,
        product_variant_id,
        firmware_version_id,
        fw_ansi.c_str(),
        protocol_version,
        role_capability_bits,
        change_count,
        session_id,
        sequence_num,
        citizen_key,
        message_id
    );

    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"Failed to build announce packet: error %d", result));
        error_count++;
        return false;
    }

    last_packet_size = buffer.GetSize();

    bool transmit_success = true;

    if (socket_initialized && udp_socket != INVALID_SOCKET) {
        // Set multicast source interface only for explicit non-loopback selection.
        if (selected_nic_ip != "127.0.0.1") {
            struct in_addr iface_addr;
            iface_addr.s_addr = inet_addr(selected_nic_ip.c_str());
            if (iface_addr.s_addr == INADDR_NONE) {
                LogError("Invalid selected NIC IP; using OS default multicast interface.");
            } else {
                if (setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_IF,
                               (char*)&iface_addr, sizeof(iface_addr)) == SOCKET_ERROR) {
                    int if_err = WSAGetLastError();
                    LogError(String().sprintf(L"IP_MULTICAST_IF failed: WSA error %d; using OS default interface", if_err));
                }
            }
        }

        sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(SigNet::SIGNET_UDP_PORT);
        dest_addr.sin_addr.s_addr = inet_addr(SigNet::MULTICAST_NODE_SEND_IP);

        int bytes_sent = sendto(
            udp_socket,
            (const char*)buffer.GetBuffer(),
            buffer.GetSize(),
            0,
            (sockaddr*)&dest_addr,
            sizeof(dest_addr)
        );

        if (bytes_sent == SOCKET_ERROR) {
            int err = WSAGetLastError();
            // Retry once using default interface if a selected NIC route fails.
            if (selected_nic_ip != "127.0.0.1") {
                struct in_addr any_addr;
                any_addr.s_addr = INADDR_ANY;
                setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_IF,
                           (char*)&any_addr, sizeof(any_addr));

                bytes_sent = sendto(
                    udp_socket,
                    (const char*)buffer.GetBuffer(),
                    buffer.GetSize(),
                    0,
                    (sockaddr*)&dest_addr,
                    sizeof(dest_addr)
                );
                if (bytes_sent != SOCKET_ERROR) {
                    LogMessage("Announce retry succeeded using default multicast interface.");
                }
            }

            if (bytes_sent == SOCKET_ERROR) {
                err = WSAGetLastError();
                LogError(String().sprintf(L"Announce sendto() failed: WSA error %d", err));
                error_count++;
                transmit_success = false;
            }
        }
        if (bytes_sent != buffer.GetSize()) {
            LogError(String().sprintf(L"Announce partial send: %d of %d bytes", bytes_sent, buffer.GetSize()));
            error_count++;
            transmit_success = false;
        }
    } else {
        LogError("Socket not initialized - cannot send announce packets");
        error_count++;
        transmit_success = false;
    }

    if (!transmit_success) {
        return false;
    }

    send_count++;
    sequence_num = SigNet::IncrementSequence(sequence_num);
    message_id++;

    if (SigNet::ShouldIncrementSession(sequence_num)) {
        session_id++;
        sequence_num = 1;
        LogMessage(String().sprintf(L"Session rolled over to %u", session_id));
    }

    EditSequence->Text = String().sprintf(L"%u", sequence_num);
    EditMessageID->Text = String().sprintf(L"%u", message_id);
    EditSessionID->Text = String().sprintf(L"%u", session_id);

    return true;
}
//---------------------------------------------------------------------------

// Update status display
void TFormSigNetTest::UpdateStatusDisplay()
{
    // This would be called periodically to update statistics
    // For now, status is updated via LogMessage calls
}
//---------------------------------------------------------------------------

// Log info message
void TFormSigNetTest::LogMessage(const String& msg)
{
    String timestamp = FormatDateTime("hh:nn:ss", Now());
    MemoStatus->Lines->Add("[" + timestamp + "] " + msg);
    
    // Auto-scroll to bottom
    MemoStatus->SelStart = MemoStatus->GetTextLen();
    MemoStatus->SelLength = 0;
    MemoStatus->Perform(EM_SCROLLCARET, 0, 0);
    
    // Limit to 100 lines
    while (MemoStatus->Lines->Count > 100) {
        MemoStatus->Lines->Delete(0);
    }
}
//---------------------------------------------------------------------------

// Log error message
void TFormSigNetTest::LogError(const String& msg)
{
    LogMessage("ERROR: " + msg);
}
//---------------------------------------------------------------------------

// Parse K0 from 64-character hex string
bool TFormSigNetTest::ParseK0FromHex(const String& hex_string)
{
    if (hex_string.Length() != 64) {
        return false;
    }
    
    for (int i = 0; i < 32; i++) {
        String byte_str = hex_string.SubString(i * 2 + 1, 2);
        
        try {
            k0_key[i] = StrToInt("0x" + byte_str);
        }
        catch (...) {
            return false;
        }
    }
    
    return true;
}
//---------------------------------------------------------------------------

// Parse TUID from 12-character hex string
bool TFormSigNetTest::ParseTUIDFromHex(const String& hex_string)
{
    if (hex_string.Length() != 12) {
        return false;
    }
    
    for (int i = 0; i < 6; i++) {
        String byte_str = hex_string.SubString(i * 2 + 1, 2);
        
        try {
            tuid[i] = StrToInt("0x" + byte_str);
        }
        catch (...) {
            return false;
        }
    }
    
    return true;
}
//---------------------------------------------------------------------------

// Create DMX fader controls (512 trackbars with labels)
void TFormSigNetTest::CreateDMXFaderControls()
{
    for (int i = 0; i < DMX_VISIBLE_COUNT; i++) {
        // Trackbar (Tag = slot index 0-31)
        TTrackBar* tb = new TTrackBar(PanelTrackbars);
        tb->Parent = PanelTrackbars;
        tb->Min = 0;
        tb->Max = 255;
        tb->Position = 255 - dmx_buffer[i];
        tb->Orientation = trVertical;
        tb->Width = 20;
        tb->Height = 150;
        tb->Left = 0;
        tb->Top = 0;
        tb->TickStyle = tsNone;
        tb->Tag = i;  // Slot index (0-31); channel = Tag + dmx_scroll_position
        tb->OnChange = TrackBarDMXChange;
        
        // Label below trackbar showing channel number
        TLabel* lbl = new TLabel(PanelTrackbars);
        lbl->Parent = PanelTrackbars;
        lbl->Caption = IntToStr(i + 1);  // Will be updated on scroll
        lbl->Transparent = true;
        lbl->Font->Height = -10;
        lbl->AutoSize = false;
        lbl->Width = 20;
        lbl->Height = 14;
        lbl->Left = 0;
        lbl->Top = 0;
        lbl->Alignment = taCenter;
        
        dmx_trackbars[i] = tb;
        dmx_labels[i] = lbl;
    }

    LayoutDMXFaderControls();
    
    UpdateDMXFaderDisplay();
}
//---------------------------------------------------------------------------

void TFormSigNetTest::LayoutDMXFaderControls()
{
    if (!PanelTrackbars) {
        return;
    }

    const int LEFT_MARGIN = 8;
    const int RIGHT_MARGIN = 8;
    const int TOP_MARGIN = 4;
    const int SLOT_GAP = 2;
    const int LABEL_GAP = 4;
    const int LABEL_HEIGHT = 14;
    const int BOTTOM_MARGIN = 4;

    int available_width = PanelTrackbars->ClientWidth - LEFT_MARGIN - RIGHT_MARGIN - ((DMX_VISIBLE_COUNT - 1) * SLOT_GAP);
    if (available_width < DMX_VISIBLE_COUNT) {
        available_width = DMX_VISIBLE_COUNT;
    }

    int trackbar_height = PanelTrackbars->ClientHeight - TOP_MARGIN - LABEL_GAP - LABEL_HEIGHT - BOTTOM_MARGIN;
    if (trackbar_height < 40) {
        trackbar_height = 40;
    }

    int base_width = available_width / DMX_VISIBLE_COUNT;
    int extra_pixels = available_width % DMX_VISIBLE_COUNT;
    int x = LEFT_MARGIN;

    for (int i = 0; i < DMX_VISIBLE_COUNT; i++) {
        int width = base_width;
        if (i < extra_pixels) {
            width++;
        }

        if (dmx_trackbars[i]) {
            dmx_trackbars[i]->SetBounds(x, TOP_MARGIN, width, trackbar_height);
        }

        if (dmx_labels[i]) {
            dmx_labels[i]->SetBounds(x, TOP_MARGIN + trackbar_height + LABEL_GAP, width, LABEL_HEIGHT);
        }

        x += width + SLOT_GAP;
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTest::PanelTrackbarsResize(TObject *Sender)
{
    LayoutDMXFaderControls();
}
//---------------------------------------------------------------------------

// Update all 32 trackbar values and labels from the buffer at current offset
void TFormSigNetTest::UpdateDMXFaderDisplay()
{
    for (int i = 0; i < DMX_VISIBLE_COUNT; i++) {
        int channel = dmx_scroll_position + i;  // 0-based buffer index
        // Suppress OnChange while reloading values
        dmx_trackbars[i]->OnChange = NULL;
        dmx_trackbars[i]->Position = 255 - dmx_buffer[channel];
        dmx_trackbars[i]->OnChange = TrackBarDMXChange;
        dmx_labels[i]->Caption = IntToStr(channel + 1);  // 1-based display
    }
}
//---------------------------------------------------------------------------

// Handle scrollbar change — update internal offset and reload the 32 trackbars
void __fastcall TFormSigNetTest::ScrollBarDMXChange(TObject *Sender)
{
    dmx_scroll_position = ScrollBarDMX->Position;
    UpdateDMXFaderDisplay();
}
//---------------------------------------------------------------------------

// Handle trackbar change — Tag is slot 0-31; actual channel = slot + scroll offset
void __fastcall TFormSigNetTest::TrackBarDMXChange(TObject *Sender)
{
    if (ComboBoxDmxMode->ItemIndex != 0) {
        return;
    }

    TTrackBar* tb = dynamic_cast<TTrackBar*>(Sender);
    if (tb) {
        int channel = tb->Tag + dmx_scroll_position;
        if (channel >= 0 && channel < 512) {
            // Inverted UI mapping: 255 on slider equals 0 in DMX buffer
            dmx_buffer[channel] = static_cast<uint8_t>(255 - tb->Position);
            SendPacket();
        }
    }
}
//---------------------------------------------------------------------------

// Reload the 32 visible trackbars after a pattern change
void TFormSigNetTest::SyncTrackbarsFromBuffer()
{
    UpdateDMXFaderDisplay();
}
//---------------------------------------------------------------------------

void TFormSigNetTest::UpdateK0DependentControls()
{
    ButtonSendAnnounce->Enabled = k0_set;
    ButtonSendLevelPacket->Enabled = k0_set;
    GroupBoxDMXFaders->Enabled = k0_set;
    // Disarm keep-alive if K0 is no longer valid
    if (!k0_set) {
        TimerKeepAlive->Enabled = false;
        CheckKeepAlive->Checked = false;
    }
}
//---------------------------------------------------------------------------
