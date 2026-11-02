module hammer_v3_uart (
    input wire clk, rst_n, uart_rx,
    output wire uart_tx, irq,
    input wire req_valid, req_write,
    input wire [63:0] req_addr,
    input wire [1:0] req_size,
    input wire [63:0] req_wdata,
    input wire [7:0] req_wstrb,
    output wire req_ready,
    output wire rsp_valid,
    input wire rsp_ready,
    output wire [63:0] rsp_rdata,
    output wire rsp_error
);
    localparam [2:0] TX_IDLE=0, TX_START=1, TX_DATA=2, TX_PARITY=3, TX_STOP=4;
    localparam [3:0] RX_IDLE=0, RX_START=1, RX_DATA=2, RX_PARITY=3,
        RX_STOP=4, RX_TAIL=5, RX_COMMIT=6, RX_BREAK=7;
    reg [7:0] ier, lcr, mcr, scr;
    reg [15:0] divisor;
    reg fifo_enabled;
    reg [1:0] trigger_level;
    (* nomem2reg *) reg [7:0] tx_fifo [0:15];
    (* nomem2reg *) reg [7:0] rx_fifo [0:15];
    reg [2:0] rx_errors [0:15];
    reg [3:0] tx_head, tx_tail, rx_head, rx_tail;
    reg [4:0] tx_count, rx_count;
    reg overrun, thre_pending;
    reg [3:0] modem_previous, modem_delta;
    reg response_q, error_q;
    reg [63:0] response_data;
    reg rx_meta, rx_sync;
    reg [2:0] tx_state;
    reg [3:0] rx_state;
    reg [7:0] tx_shift, tx_format, rx_shift, rx_format;
    reg [2:0] tx_bit, rx_bit;
    reg tx_parity;
    reg [5:0] tx_ticks, rx_ticks;
    reg [15:0] tx_divisor, rx_divisor, tx_clock, rx_clock;
    reg rx_xor, rx_parity_error, rx_frame_error, rx_all_low, rx_break_error;
    reg [15:0] timeout_clock;
    reg [9:0] timeout_ticks;
    reg timeout_pending;
    wire [15:0] effective_divisor = divisor == 0 ? 16'd1 : divisor;
    wire [4:0] capacity = fifo_enabled ? 5'd16 : 5'd1;
    wire [7:0] write_byte = req_wdata >> {req_addr[2:0],3'b0};
    wire [2:0] offset = req_addr[2:0];
    wire geometry_ok = req_addr >= 64'h10010000 && req_addr < 64'h10010008 &&
        req_size == 0 && req_wstrb == (8'h01 << req_addr[2:0]);
    wire slot = rst_n && req_valid && !response_q;
    wire raw_fcr_write = slot && geometry_ok && req_write && offset == 2;
    wire rx_clear = raw_fcr_write && (write_byte[1] || write_byte[0] != fifo_enabled);
    wire tx_clear = raw_fcr_write && (write_byte[2] || write_byte[0] != fifo_enabled);
    wire tx_pop = rst_n && tx_state == TX_IDLE && tx_count != 0 && !tx_clear;
    wire is_thr_write = geometry_ok && req_write && offset == 0 && !lcr[7];
    assign req_ready = rst_n && !response_q &&
        !(is_thr_write && tx_count >= capacity && !tx_pop);
    wire accept = req_valid && req_ready;
    wire bus_valid = accept && geometry_ok;
    wire tx_push = bus_valid && is_thr_write;
    wire rx_pop = bus_valid && !req_write && offset == 0 && !lcr[7] && rx_count != 0;
    wire rx_arrival = rst_n && rx_state == RX_COMMIT;
    wire rx_push = rx_arrival && (rx_count < capacity || rx_pop);
    wire lsr_read = bus_valid && !req_write && offset == 5;
    wire msr_read = bus_valid && !req_write && offset == 6;
    wire iir_read = bus_valid && !req_write && offset == 2;
    wire ier_write = bus_valid && req_write && offset == 1 && !lcr[7];
    wire [7:0] data_mask = 8'hff >> (3 - lcr[1:0]);
    wire tx_line = lcr[6] ? 1'b0 :
        tx_state == TX_START ? 1'b0 :
        tx_state == TX_DATA ? tx_shift[0] :
        tx_state == TX_PARITY ? tx_parity : 1'b1;
    wire rx_line = mcr[4] ? tx_line : rx_sync;
    wire [3:0] modem_now = mcr[4] ? {mcr[3],mcr[2],mcr[0],mcr[1]} : 4'b0;
    wire [3:0] modem_change = {
        modem_now[3] ^ modem_previous[3],
        modem_previous[2] && !modem_now[2],
        modem_now[1] ^ modem_previous[1],
        modem_now[0] ^ modem_previous[0]
    };
    reg [4:0] rx_trigger;
    reg [7:0] lsr_value, iir_value, read_byte;
    reg fifo_error;
    reg [3:0] active_slot;
    wire [9:0] character_ticks = 10'd16 + ((10'd5 + {8'b0,lcr[1:0]}) << 4) +
        (lcr[3] ? 10'd16 : 10'd0) +
        (lcr[2] ? (lcr[1:0] == 0 ? 10'd24 : 10'd32) : 10'd16);
    wire [9:0] timeout_limit = character_ticks << 2;
    integer k, n;

    assign uart_tx = !rst_n || mcr[4] ? 1'b1 : tx_line;
    assign irq = rst_n && !iir_value[0];
    assign rsp_valid = rst_n && response_q;
    assign rsp_error = rsp_valid && error_q;
    assign rsp_rdata = rsp_valid && !error_q ? response_data : 64'b0;

    always @* begin
        case (trigger_level)
            2'd0: rx_trigger = 5'd1;
            2'd1: rx_trigger = 5'd4;
            2'd2: rx_trigger = 5'd8;
            default: rx_trigger = 5'd14;
        endcase
        if (!fifo_enabled) rx_trigger = 5'd1;
        fifo_error = 1'b0;
        active_slot = 4'b0;
        for (k = 0; k < 16; k = k + 1) begin
            active_slot = rx_head + k;
            if (k < rx_count && |rx_errors[active_slot]) fifo_error = 1'b1;
        end
        lsr_value = 8'b0;
        lsr_value[0] = rx_count != 0;
        lsr_value[1] = overrun;
        if (rx_count != 0) lsr_value[4:2] = rx_errors[rx_head];
        lsr_value[5] = tx_count == 0;
        lsr_value[6] = tx_count == 0 && tx_state == TX_IDLE;
        lsr_value[7] = fifo_enabled && fifo_error;
        iir_value = fifo_enabled ? 8'hc1 : 8'h01;
        if (ier[2] && |lsr_value[4:1]) iir_value[3:0] = 4'h6;
        else if (ier[0] && rx_count >= rx_trigger) iir_value[3:0] = 4'h4;
        else if (ier[0] && fifo_enabled && rx_count != 0 && timeout_pending)
            iir_value[3:0] = 4'hc;
        else if (ier[1] && thre_pending) iir_value[3:0] = 4'h2;
        else if (ier[3] && |modem_delta) iir_value[3:0] = 4'h0;
        read_byte = 8'b0;
        case (offset)
            3'd0: begin
                if (lcr[7]) read_byte = divisor[7:0];
                else if (rx_count != 0) read_byte = rx_fifo[rx_head];
            end
            3'd1: read_byte = lcr[7] ? divisor[15:8] : ier;
            3'd2: read_byte = iir_value;
            3'd3: read_byte = lcr;
            3'd4: read_byte = mcr;
            3'd5: read_byte = lsr_value;
            3'd6: read_byte = {modem_now,modem_delta};
            3'd7: read_byte = scr;
        endcase
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rx_meta <= 1'b1;
            rx_sync <= 1'b1;
            ier <= 8'b0;
            lcr <= 8'b0;
            mcr <= 8'b0;
            scr <= 8'b0;
            divisor <= 16'd1;
            fifo_enabled <= 1'b0;
            trigger_level <= 2'b0;
            response_q <= 1'b0;
            error_q <= 1'b0;
            response_data <= 64'b0;
            modem_previous <= 4'b0;
            modem_delta <= 4'b0;
            thre_pending <= 1'b0;
        end else begin
            rx_meta <= uart_rx;
            rx_sync <= rx_meta;
            modem_previous <= modem_now;
            modem_delta <= (msr_read ? 4'b0 : modem_delta) | modem_change;
            if (response_q && rsp_ready) begin
                response_q <= 1'b0;
                error_q <= 1'b0;
                response_data <= 64'b0;
            end
            if (accept) begin
                response_q <= 1'b1;
                error_q <= !geometry_ok;
                response_data <= 64'b0;
                if (geometry_ok) begin
                    if (!req_write)
                        response_data <= {56'b0,read_byte} << {req_addr[2:0],3'b0};
                    else begin
                        case (offset)
                            3'd0: if (lcr[7]) divisor[7:0] <= write_byte;
                            3'd1: begin
                                if (lcr[7]) divisor[15:8] <= write_byte;
                                else ier <= write_byte & 8'h0f;
                            end
                            3'd2: begin
                                fifo_enabled <= write_byte[0];
                                trigger_level <= write_byte[7:6];
                            end
                            3'd3: lcr <= write_byte;
                            3'd4: mcr <= write_byte & 8'h1f;
                            3'd7: scr <= write_byte;
                            default: begin end
                        endcase
                    end
                end
            end
            if (!ier[1]) thre_pending <= 1'b0;
            if (ier[1] && ((tx_pop && tx_count == 1 && !tx_push) || tx_clear))
                thre_pending <= 1'b1;
            if (iir_read && iir_value[3:0] == 2) thre_pending <= 1'b0;
            if (tx_push) thre_pending <= 1'b0;
            if (ier_write) begin
                if (!write_byte[1]) thre_pending <= 1'b0;
                else if (!ier[1] && tx_count == 0) thre_pending <= 1'b1;
            end
        end
    end

    always @(posedge clk) begin
        if (rst_n && tx_push && !tx_clear) tx_fifo[tx_tail] <= write_byte;
        if (rst_n && rx_push && !rx_clear) rx_fifo[rx_tail] <= rx_shift;
    end
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            tx_head <= 4'b0;
            tx_tail <= 4'b0;
            rx_head <= 4'b0;
            rx_tail <= 4'b0;
            tx_count <= 5'b0;
            rx_count <= 5'b0;
            overrun <= 1'b0;
            for (n = 0; n < 16; n = n + 1) rx_errors[n] <= 3'b0;
        end else begin
            if (tx_clear) begin
                tx_head <= 4'b0;
                tx_tail <= 4'b0;
                tx_count <= 5'b0;
            end else begin
                case ({tx_push,tx_pop})
                    2'b10: tx_count <= tx_count + 1'b1;
                    2'b01: tx_count <= tx_count - 1'b1;
                    default: begin end
                endcase
                if (tx_push) tx_tail <= tx_tail + 1'b1;
                if (tx_pop) tx_head <= tx_head + 1'b1;
            end
            if (rx_clear) begin
                rx_head <= 4'b0;
                rx_tail <= 4'b0;
                rx_count <= 5'b0;
                overrun <= 1'b0;
                for (n = 0; n < 16; n = n + 1) rx_errors[n] <= 3'b0;
            end else begin
                if (lsr_read) begin
                    overrun <= 1'b0;
                    if (rx_count != 0) rx_errors[rx_head] <= 3'b0;
                end
                case ({rx_push,rx_pop})
                    2'b10: rx_count <= rx_count + 1'b1;
                    2'b01: rx_count <= rx_count - 1'b1;
                    default: begin end
                endcase
                if (rx_pop) begin
                    rx_head <= rx_head + 1'b1;
                    rx_errors[rx_head] <= 3'b0;
                end
                if (rx_push) begin
                    rx_tail <= rx_tail + 1'b1;
                    rx_errors[rx_tail] <= {rx_break_error,rx_frame_error,rx_parity_error};
                end
                if (rx_arrival && !rx_push) overrun <= 1'b1;
            end
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            tx_state <= TX_IDLE;
            tx_shift <= 8'b0;
            tx_format <= 8'b0;
            tx_bit <= 3'b0;
            tx_parity <= 1'b0;
            tx_ticks <= 6'b0;
            tx_divisor <= 16'd1;
            tx_clock <= 16'b0;
        end else if (tx_state == TX_IDLE) begin
            if (tx_pop) begin
                tx_shift <= tx_fifo[tx_head] & data_mask;
                tx_format <= lcr;
                tx_bit <= 3'b0;
                tx_parity <= lcr[5] ? !lcr[4] :
                    lcr[4] ? ^(tx_fifo[tx_head] & data_mask) :
                    ~^(tx_fifo[tx_head] & data_mask);
                tx_divisor <= effective_divisor;
                tx_clock <= effective_divisor - 1'b1;
                tx_ticks <= 6'd15;
                tx_state <= TX_START;
            end
        end else if (tx_clock != 0) tx_clock <= tx_clock - 1'b1;
        else begin
            tx_clock <= tx_divisor - 1'b1;
            if (tx_ticks != 0) tx_ticks <= tx_ticks - 1'b1;
            else begin
                tx_ticks <= 6'd15;
                case (tx_state)
                    TX_START: tx_state <= TX_DATA;
                    TX_DATA: begin
                        if (tx_bit == (3'd4 + {1'b0,tx_format[1:0]})) begin
                            if (tx_format[3]) tx_state <= TX_PARITY;
                            else begin
                                tx_state <= TX_STOP;
                                tx_ticks <= tx_format[2] ?
                                    (tx_format[1:0] == 0 ? 6'd23 : 6'd31) : 6'd15;
                            end
                        end else begin
                            tx_shift <= {1'b0,tx_shift[7:1]};
                            tx_bit <= tx_bit + 1'b1;
                        end
                    end
                    TX_PARITY: begin
                        tx_state <= TX_STOP;
                        tx_ticks <= tx_format[2] ?
                            (tx_format[1:0] == 0 ? 6'd23 : 6'd31) : 6'd15;
                    end
                    TX_STOP: tx_state <= TX_IDLE;
                    default: tx_state <= TX_IDLE;
                endcase
            end
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rx_state <= RX_IDLE;
            rx_shift <= 8'b0;
            rx_format <= 8'b0;
            rx_bit <= 3'b0;
            rx_ticks <= 6'b0;
            rx_divisor <= 16'd1;
            rx_clock <= 16'b0;
            rx_xor <= 1'b0;
            rx_parity_error <= 1'b0;
            rx_frame_error <= 1'b0;
            rx_all_low <= 1'b1;
            rx_break_error <= 1'b0;
        end else if (rx_state == RX_IDLE) begin
            if (!rx_line) begin
                rx_shift <= 8'b0;
                rx_format <= lcr;
                rx_bit <= 3'b0;
                rx_divisor <= effective_divisor;
                rx_clock <= effective_divisor - 1'b1;
                rx_ticks <= 6'd7;
                rx_xor <= 1'b0;
                rx_parity_error <= 1'b0;
                rx_frame_error <= 1'b0;
                rx_all_low <= 1'b1;
                rx_break_error <= 1'b0;
                rx_state <= RX_START;
            end
        end else if (rx_state == RX_COMMIT) begin
            if (rx_break_error) rx_state <= RX_BREAK;
            else rx_state <= RX_IDLE;
        end else if (rx_state == RX_BREAK) begin
            if (rx_line) rx_state <= RX_IDLE;
        end else if (rx_clock != 0) rx_clock <= rx_clock - 1'b1;
        else begin
            rx_clock <= rx_divisor - 1'b1;
            if (rx_ticks != 0) rx_ticks <= rx_ticks - 1'b1;
            else begin
                rx_ticks <= 6'd15;
                case (rx_state)
                    RX_START: begin
                        if (rx_line) rx_state <= RX_IDLE;
                        else rx_state <= RX_DATA;
                    end
                    RX_DATA: begin
                        rx_shift[rx_bit] <= rx_line;
                        rx_xor <= rx_xor ^ rx_line;
                        if (rx_line) rx_all_low <= 1'b0;
                        if (rx_bit == (3'd4 + {1'b0,rx_format[1:0]})) begin
                            if (rx_format[3]) rx_state <= RX_PARITY;
                            else rx_state <= RX_STOP;
                        end else rx_bit <= rx_bit + 1'b1;
                    end
                    RX_PARITY: begin
                        rx_parity_error <= rx_line != (rx_format[5] ?
                            !rx_format[4] : (rx_format[4] ? rx_xor : !rx_xor));
                        if (rx_line) rx_all_low <= 1'b0;
                        rx_state <= RX_STOP;
                    end
                    RX_STOP: begin
                        rx_frame_error <= !rx_line;
                        if (rx_line) rx_all_low <= 1'b0;
                        if (rx_format[2]) begin
                            rx_ticks <= rx_format[1:0] == 0 ? 6'd11 : 6'd15;
                            rx_state <= RX_TAIL;
                        end else begin
                            rx_break_error <= rx_all_low && !rx_line;
                            rx_state <= RX_COMMIT;
                        end
                    end
                    RX_TAIL: begin
                        rx_frame_error <= rx_frame_error || !rx_line;
                        rx_break_error <= rx_all_low && !rx_line;
                        rx_state <= RX_COMMIT;
                    end
                    default: rx_state <= RX_IDLE;
                endcase
            end
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            timeout_clock <= 16'b0;
            timeout_ticks <= 10'b0;
            timeout_pending <= 1'b0;
        end else if (!fifo_enabled || rx_count == 0 || rx_arrival || rx_pop || rx_clear) begin
            timeout_clock <= effective_divisor - 1'b1;
            timeout_ticks <= 10'b0;
            timeout_pending <= 1'b0;
        end else if (!timeout_pending) begin
            if (timeout_clock != 0) timeout_clock <= timeout_clock - 1'b1;
            else begin
                timeout_clock <= effective_divisor - 1'b1;
                if (timeout_ticks + 1'b1 >= timeout_limit) timeout_pending <= 1'b1;
                else timeout_ticks <= timeout_ticks + 1'b1;
            end
        end
    end
endmodule
