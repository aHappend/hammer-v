module hammer_v2_clint (
    input wire clk, rst_n,
    input wire req_valid,
    output wire req_ready,
    input wire req_write,
    input wire [1:0] req_size,
    input wire [63:0] req_addr, req_wdata,
    input wire [7:0] req_wstrb,
    output wire rsp_valid,
    input wire rsp_ready,
    output wire [63:0] rsp_rdata,
    output wire rsp_error,
    output wire [63:0] mtime,
    output wire irq_msip, irq_mtip
);
    reg [63:0] time_q, cmp_q, read_q;
    reg msip_q, response, error_q;
    reg [1:0] selection;
    reg bad;
    reg [63:0] snapshot, merged;
    integer lane;
    wire accept = req_valid && req_ready;
    wire [63:0] aligned = {req_addr[63:3],3'b0};
    wire [3:0] extent = 4'd1 << req_size;
    wire [3:0] end_offset = {1'b0,req_addr[2:0]} + extent;
    wire misaligned = (req_size == 1 && req_addr[0]) ||
        (req_size == 2 && |req_addr[1:0]) ||
        (req_size == 3 && |req_addr[2:0]);
    assign req_ready = rst_n && !response;
    assign rsp_valid = rst_n && response;
    assign rsp_rdata = rsp_valid ? read_q : 64'b0;
    assign rsp_error = rsp_valid && error_q;
    assign mtime = rst_n ? time_q : 64'b0;
    assign irq_msip = rst_n && msip_q;
    assign irq_mtip = rst_n && time_q >= cmp_q;
    always @* begin
        selection = 2'b0;
        snapshot = 64'b0;
        bad = misaligned;
        case (aligned)
            64'h02000000: begin
                selection = 2'd1;
                snapshot = {63'b0,msip_q};
                if (end_offset > 4) bad = 1'b1;
            end
            64'h02004000: begin
                selection = 2'd2;
                snapshot = cmp_q;
                if (end_offset > 8) bad = 1'b1;
            end
            64'h0200bff8: begin
                selection = 2'd3;
                snapshot = time_q;
                if (end_offset > 8) bad = 1'b1;
            end
            default: bad = 1'b1;
        endcase
        merged = snapshot;
        for (lane = 0; lane < 8; lane = lane + 1)
            if (req_wstrb[lane])
                merged[lane*8 +: 8] = req_wdata[lane*8 +: 8];
    end
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            time_q <= 64'b0;
            cmp_q <= 64'hffffffffffffffff;
            msip_q <= 1'b0;
            response <= 1'b0;
            error_q <= 1'b0;
            read_q <= 64'b0;
        end else begin
            time_q <= time_q + 64'd1;
            if (rsp_valid && rsp_ready) response <= 1'b0;
            if (accept) begin
                response <= 1'b1;
                error_q <= bad;
                read_q <= bad ? 64'b0 : snapshot;
                if (req_write && !bad) begin
                    case (selection)
                        1: if (req_wstrb[0]) msip_q <= req_wdata[0];
                        2: cmp_q <= merged;
                        3: if (|req_wstrb) time_q <= merged;
                        default: begin end
                    endcase
                end
            end
        end
    end
endmodule
