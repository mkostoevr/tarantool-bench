function gen_single_plot {
    local x_label="Latency (µs)"
    local y_label="Percentile"
    if [[ "$3" == hist ]]; then
        y_label="Requests"
    fi
    gnuplot -e "input_file='data/${1}_${2}_${3}.txt'; output_file='plots/${1}_${2}_${3}.png'; xbegin=$4; xend=$5; brief='$1'; main_title='Tarantool $2'; x_label='$x_label'; y_label='$y_label'" plot.p &&
    firefox "plots/${1}_${2}_${3}.png" &
}

function gen4 {
    local v=$1;
    local xbegin=$2;
    local xend=$3;
    gnuplot -e "input_ping='data/ping_${v}_hist.txt'; \
                input_insert='data/insert_${v}_hist.txt'; \
                input_select='data/select_${v}_hist.txt'; \
                input_delete='data/delete_${v}_hist.txt'; \
                output_file='plots/all_${v}_hist.png'; xbegin=$xbegin; xend=$xend; main_title='Tarantool $v'" plot_all.p &&
    firefox "plots/all_${v}_hist.png" &
}

function gen_vs_plot {
    local func="$1";
    local yend="$2";
    gnuplot -e "input_a='data/${func}_1.5_rcdf.txt'; \
                input_b='data/${func}_3.0_rcdf.txt'; \
                output_file='plots/${func}_1.5vs3.0_rcdf.png'; xbegin=0; xend=0.999; ybegin=0; yend=$yend; main_title='Tarantool 1.5 vs 3.0 ($func)'; brief_a='1.5'; brief_b='3.0'; x_label='Percentile'; y_label='Latency (µs)'" plot_vs.p;
    firefox "plots/${func}_1.5vs3.0_hist.png" &
}

function gen_vs_plots {
    gen_vs_plot ping 40000;
    gen_vs_plot insert 60000;
    gen_vs_plot select 40000;
    gen_vs_plot delete 60000;
}

function gen_single_plots {
    gen_single_plot ping 1.5 hist 19500 20500
    gen_single_plot ping 1.5 cdf 19500 20500
    gen_single_plot insert 1.5 hist 34750 41000
    gen_single_plot insert 1.5 cdf 34750 41000
    gen_single_plot select 1.5 hist 19500 21500
    gen_single_plot select 1.5 cdf 19500 21500
    gen_single_plot delete 1.5 hist 34750 40000
    gen_single_plot delete 1.5 cdf 34750 40000
    gen_single_plot ping 3.0 hist 32570 33570
    gen_single_plot ping 3.0 cdf 32570 33570
    gen_single_plot insert 3.0 hist 49500 54500
    gen_single_plot insert 3.0 cdf 49500 54500
    gen_single_plot delete 3.0 hist 49500 54500
    gen_single_plot delete 3.0 cdf 49500 54500
    gen_single_plot select 3.0 hist 33100 34200
    gen_single_plot select 3.0 cdf 33100 34200
}

function gen_all_plots {
    gen_single_plots;
    gen_vs_plots;
}
