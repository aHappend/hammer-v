module hammer_v3_plic (
    input wire clk, rst_n,
    input wire uart_irq,
    input wire [30:0] plic_sources,
    output wire irq_meip, irq_seip,
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
    reg [32:1] source_meta, source_sync, pending, in_service, owner;
    reg [2:0] priority_q [0:32];
    reg [32:1] enable_q [0:1];
    reg [2:0] threshold [0:1];
    reg response_q, error_q, meip_q, seip_q;
    reg [63:0] data_q;
    wire [8:0] rank [0:1][1:63];
    wire [5:0] selected [0:1];
    wire accept = req_valid && req_ready;
    wire [31:0] write_word = req_addr[2] ? req_wdata[63:32] : req_wdata[31:0];
    wire [7:0] word_mask = req_addr[2] ? 8'hf0 : 8'h0f;
    wire geometry_ok = req_size == 2 && req_addr[1:0] == 0 &&
        req_wstrb == word_mask;
    reg decoded, readonly_q;
    reg [2:0] register_kind;
    reg context_id, upper_word;
    reg [5:0] priority_id;
    reg [31:0] read_word;
    localparam [2:0] PRIORITY=0, PENDING=1, ENABLE=2, THRESHOLD=3, CLAIM=4;
    wire valid_access = accept && geometry_ok && decoded &&
        !(req_write && readonly_q);
    wire claiming = valid_access && !req_write && register_kind == CLAIM;
    wire completing = valid_access && req_write && register_kind == CLAIM;
    wire [5:0] claim_id = selected[context_id];
    wire completion_in_range = write_word >= 1 && write_word <= 32;
    wire [5:0] completion_id = write_word[5:0];
    wire completion_valid = completing && completion_in_range &&
        in_service[completion_id] && owner[completion_id] == context_id;
    integer n;

    generate for (genvar c = 0; c < 2; c = c + 1) begin : g_context
        for (genvar s = 0; s < 32; s = s + 1) begin : g_source
            localparam [5:0] SOURCE_ID = s + 1;
            assign rank[c][32+s] =
                pending[s+1] && !in_service[s+1] && enable_q[c][s+1] &&
                priority_q[s+1] > threshold[c] ?
                {priority_q[s+1],~SOURCE_ID} : 9'b0;
        end
        for (genvar t = 1; t < 32; t = t + 1) begin : g_tree
            assign rank[c][t] = rank[c][2*t] >= rank[c][2*t+1] ?
                rank[c][2*t] : rank[c][2*t+1];
        end
        assign selected[c] = |rank[c][1][8:6] ? ~rank[c][1][5:0] : 6'b0;
    end endgenerate

    assign req_ready = rst_n && !response_q;
    assign rsp_valid = rst_n && response_q;
    assign rsp_error = rsp_valid && error_q;
    assign rsp_rdata = rsp_valid && !error_q ? data_q : 64'b0;
    assign irq_meip = rst_n && meip_q;
    assign irq_seip = rst_n && seip_q;

    always @* begin
        decoded = 1'b0;
        readonly_q = 1'b0;
        register_kind = PRIORITY;
        context_id = 1'b0;
        upper_word = 1'b0;
        priority_id = 6'b0;
        read_word = 32'b0;
        if (req_addr >= 64'h0c000000 && req_addr <= 64'h0c000080) begin
            decoded = 1'b1;
            register_kind = PRIORITY;
            priority_id = req_addr[7:2];
            read_word = {29'b0,priority_q[priority_id]};
        end else begin
            case (req_addr)
                64'h0c001000,64'h0c001004: begin
                    decoded = 1'b1;
                    readonly_q = 1'b1;
                    register_kind = PENDING;
                    upper_word = req_addr[2];
                    read_word = req_addr[2] ? {31'b0,pending[32]} :
                        {pending[31:1],1'b0};
                end
                64'h0c002000,64'h0c002004,
                64'h0c002080,64'h0c002084: begin
                    decoded = 1'b1;
                    register_kind = ENABLE;
                    context_id = req_addr[7];
                    upper_word = req_addr[2];
                    read_word = req_addr[2] ? {31'b0,enable_q[context_id][32]} :
                        {enable_q[context_id][31:1],1'b0};
                end
                64'h0c200000,64'h0c201000: begin
                    decoded = 1'b1;
                    register_kind = THRESHOLD;
                    context_id = req_addr[12];
                    read_word = {29'b0,threshold[context_id]};
                end
                64'h0c200004,64'h0c201004: begin
                    decoded = 1'b1;
                    register_kind = CLAIM;
                    context_id = req_addr[12];
                    read_word = {26'b0,selected[context_id]};
                end
                default: begin end
            endcase
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            source_meta <= 32'b0;
            source_sync <= 32'b0;
            pending <= 32'b0;
            in_service <= 32'b0;
            owner <= 32'b0;
            enable_q[0] <= 32'b0;
            enable_q[1] <= 32'b0;
            threshold[0] <= 3'b0;
            threshold[1] <= 3'b0;
            response_q <= 1'b0;
            error_q <= 1'b0;
            data_q <= 64'b0;
            meip_q <= 1'b0;
            seip_q <= 1'b0;
            for (n = 0; n <= 32; n = n + 1) priority_q[n] <= 3'b0;
        end else begin
            source_meta <= {plic_sources,uart_irq};
            source_sync <= source_meta;
            meip_q <= selected[0] != 0;
            seip_q <= selected[1] != 0;
            for (n = 1; n <= 32; n = n + 1)
                if (source_sync[n] && !in_service[n]) pending[n] <= 1'b1;
            if (response_q && rsp_ready) begin
                response_q <= 1'b0;
                error_q <= 1'b0;
                data_q <= 64'b0;
            end
            if (accept) begin
                response_q <= 1'b1;
                error_q <= !geometry_ok || !decoded || (req_write && readonly_q);
                data_q <= 64'b0;
                if (valid_access) begin
                    if (!req_write)
                        data_q <= req_addr[2] ? {read_word,32'b0} : {32'b0,read_word};
                    else begin
                        case (register_kind)
                            PRIORITY: if (priority_id != 0)
                                priority_q[priority_id] <= write_word[2:0];
                            ENABLE: begin
                                if (upper_word) enable_q[context_id][32] <= write_word[0];
                                else enable_q[context_id][31:1] <= write_word[31:1];
                            end
                            THRESHOLD: threshold[context_id] <= write_word[2:0];
                            default: begin end
                        endcase
                    end
                end
            end
            if (claiming && claim_id != 0) begin
                pending[claim_id] <= 1'b0;
                in_service[claim_id] <= 1'b1;
                owner[claim_id] <= context_id;
            end
            if (completion_valid) in_service[completion_id] <= 1'b0;
        end
    end
endmodule
