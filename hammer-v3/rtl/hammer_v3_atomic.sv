module hammer_v3_atomic #(
    parameter integer DMEM_WORDS = 8192
) (
    input wire clk, rst_n, start,
    output wire ready,
    input wire [4:0] op,
    input wire word_op,
    input wire [63:0] addr, operand,
    input wire invalidate, store_commit,
    input wire [63:0] store_addr,
    output wire done,
    input wire consume,
    output wire error,
    output wire [3:0] cause,
    output wire [63:0] tval, result, old_data,
    output wire mem_write,
    output wire [7:0] wmask,
    output wire [63:0] wdata,
    output wire req_valid,
    input wire req_ready,
    output wire [1:0] req_cmd,
    output wire [63:0] req_addr, req_wdata,
    output wire [7:0] req_wstrb,
    input wire rsp_valid,
    output wire rsp_ready,
    input wire [63:0] rsp_rdata,
    input wire rsp_error
);
    initial begin
        if (DMEM_WORDS < 1 || DMEM_WORDS > 8192)
            $fatal(1, "PARAMETER ERROR: atomic DMEM_WORDS must be 1..8192");
    end
    generate if (DMEM_WORDS >= 1 && DMEM_WORDS <= 8192) begin : g_legal
        localparam [2:0] IDLE=0, READ_REQ=1, READ_WAIT=2,
            COMPUTE=3, WRITE_REQ=4, WRITE_WAIT=5, DONE=6;
        localparam [63:0] LIMIT = 64'h10000000 + DMEM_WORDS * 64'd8;
        reg [2:0] state;
        reg [4:0] op_q;
        reg word_q, error_q, write_q;
        reg [3:0] cause_q;
        reg [63:0] addr_q, operand_q, result_q, old_q, wdata_q;
        reg [7:0] mask_q;
        reg reservation, reservation_word;
        reg [63:0] reservation_addr;
        reg [63:0] updated;
        reg legal_op;
        wire is_lr = op == 5'b00010;
        wire is_sc = op == 5'b00011;
        wire misaligned = word_op ? |addr[1:0] : |addr[2:0];
        wire access_bad = !((addr >= 64'h10000000 && addr < LIMIT) ||
            (addr >= 64'h80000000 && addr < 64'h100000000));
        wire reservation_match = reservation && reservation_addr == addr &&
            reservation_word == word_op;
        wire [63:0] shifted_read = rsp_rdata >> {addr_q[2:0],3'b0};
        wire [63:0] loaded = word_q ?
            {{32{shifted_read[31]}},shifted_read[31:0]} : shifted_read;
        wire overlapping_store = store_commit &&
            store_addr[63:3] == reservation_addr[63:3];
        wire [63:0] aligned_operand = word_op ?
            ({32'b0,operand[31:0]} << {addr[2:0],3'b0}) : operand;
        assign ready = rst_n && state == IDLE;
        assign done = rst_n && state == DONE;
        assign error = done && error_q;
        assign cause = error ? cause_q : 4'b0;
        assign tval = error ? addr_q : 64'b0;
        assign result = done && !error_q ? result_q : 64'b0;
        assign old_data = done && !error_q ? old_q : 64'b0;
        assign mem_write = done && !error_q && write_q;
        assign wmask = mem_write ? mask_q : 8'b0;
        assign wdata = mem_write ? wdata_q : 64'b0;
        assign req_valid = rst_n && (state == READ_REQ || state == WRITE_REQ);
        assign req_cmd = req_valid && state == WRITE_REQ ? 2'b01 : 2'b0;
        assign req_addr = req_valid ? addr_q : 64'b0;
        assign req_wdata = req_valid && state == WRITE_REQ ? wdata_q : 64'b0;
        assign req_wstrb = req_valid && state == WRITE_REQ ? mask_q : 8'b0;
        assign rsp_ready = rst_n && (state == READ_WAIT || state == WRITE_WAIT);
        always @* begin
            legal_op = 1'b1;
            case (op)
                5'b00010,5'b00011,5'b00001,5'b00000,5'b00100,
                5'b01100,5'b01000,5'b10000,5'b10100,5'b11000,
                5'b11100: begin end
                default: legal_op = 1'b0;
            endcase
            updated = 64'b0;
            case (op_q)
                5'b00001: updated = operand_q;
                5'b00000: updated = old_q + operand_q;
                5'b00100: updated = old_q ^ operand_q;
                5'b01100: updated = old_q & operand_q;
                5'b01000: updated = old_q | operand_q;
                5'b10000: begin
                    if (word_q)
                        updated = $signed(old_q[31:0]) < $signed(operand_q[31:0]) ?
                            old_q : operand_q;
                    else updated = $signed(old_q) < $signed(operand_q) ?
                        old_q : operand_q;
                end
                5'b10100: begin
                    if (word_q)
                        updated = $signed(old_q[31:0]) > $signed(operand_q[31:0]) ?
                            old_q : operand_q;
                    else updated = $signed(old_q) > $signed(operand_q) ?
                        old_q : operand_q;
                end
                5'b11000: begin
                    if (word_q)
                        updated = old_q[31:0] < operand_q[31:0] ? old_q : operand_q;
                    else updated = old_q < operand_q ? old_q : operand_q;
                end
                5'b11100: begin
                    if (word_q)
                        updated = old_q[31:0] > operand_q[31:0] ? old_q : operand_q;
                    else updated = old_q > operand_q ? old_q : operand_q;
                end
                default: updated = 64'b0;
            endcase
        end
        always @(posedge clk or negedge rst_n) begin
            if (!rst_n) begin
                state <= IDLE;
                op_q <= 5'b0;
                word_q <= 1'b0;
                error_q <= 1'b0;
                write_q <= 1'b0;
                cause_q <= 4'b0;
                addr_q <= 64'b0;
                operand_q <= 64'b0;
                result_q <= 64'b0;
                old_q <= 64'b0;
                wdata_q <= 64'b0;
                mask_q <= 8'b0;
                reservation <= 1'b0;
                reservation_word <= 1'b0;
                reservation_addr <= 64'b0;
            end else begin
                case (state)
                    IDLE: if (start) begin
                        addr_q <= addr;
                        operand_q <= operand;
                        op_q <= op;
                        word_q <= word_op;
                        error_q <= 1'b0;
                        write_q <= 1'b0;
                        cause_q <= 4'b0;
                        result_q <= 64'b0;
                        old_q <= 64'b0;
                        wdata_q <= aligned_operand;
                        mask_q <= word_op ? (8'h0f << addr[2:0]) : 8'hff;
                        if (is_sc || is_lr) reservation <= 1'b0;
                        if (!legal_op) begin
                            error_q <= 1'b1;
                            cause_q <= 4'd2;
                            state <= DONE;
                        end else if (misaligned || access_bad) begin
                            error_q <= 1'b1;
                            if (misaligned) cause_q <= is_lr ? 4'd4 : 4'd6;
                            else cause_q <= is_lr ? 4'd5 : 4'd7;
                            state <= DONE;
                        end else if (is_sc) begin
                            if (reservation_match && !invalidate && !overlapping_store)
                                state <= WRITE_REQ;
                            else begin
                                result_q <= 64'd1;
                                state <= DONE;
                            end
                        end else state <= READ_REQ;
                    end
                    READ_REQ: if (req_ready) state <= READ_WAIT;
                    READ_WAIT: if (rsp_valid) begin
                        if (rsp_error) begin
                            error_q <= 1'b1;
                            cause_q <= op_q == 5'b00010 ? 4'd5 : 4'd7;
                            state <= DONE;
                        end else begin
                            old_q <= loaded;
                            result_q <= loaded;
                            if (op_q == 5'b00010) begin
                                reservation <= 1'b1;
                                reservation_addr <= addr_q;
                                reservation_word <= word_q;
                                state <= DONE;
                            end else state <= COMPUTE;
                        end
                    end
                    COMPUTE: begin
                        if (word_q)
                            wdata_q <= {32'b0,updated[31:0]} << {addr_q[2:0],3'b0};
                        else wdata_q <= updated;
                        state <= WRITE_REQ;
                    end
                    WRITE_REQ: if (req_ready) state <= WRITE_WAIT;
                    WRITE_WAIT: if (rsp_valid) begin
                        if (rsp_error) begin
                            error_q <= 1'b1;
                            cause_q <= 4'd7;
                        end else begin
                            write_q <= 1'b1;
                            if (op_q == 5'b00011) result_q <= 64'b0;
                            if (reservation_addr[63:3] == addr_q[63:3])
                                reservation <= 1'b0;
                        end
                        state <= DONE;
                    end
                    DONE: if (consume) state <= IDLE;
                    default: state <= IDLE;
                endcase
                if (invalidate || store_commit) reservation <= 1'b0;
            end
        end
    end else begin : g_bad
        assign ready = 1'b0;
        assign done = 1'b0;
        assign error = 1'b0;
        assign cause = 4'b0;
        assign tval = 64'b0;
        assign result = 64'b0;
        assign old_data = 64'b0;
        assign mem_write = 1'b0;
        assign wmask = 8'b0;
        assign wdata = 64'b0;
        assign req_valid = 1'b0;
        assign req_cmd = 2'b0;
        assign req_addr = 64'b0;
        assign req_wdata = 64'b0;
        assign req_wstrb = 8'b0;
        assign rsp_ready = 1'b0;
    end endgenerate
endmodule
