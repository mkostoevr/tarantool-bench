function gen2 {
    gnuplot -e "input_file='data/${1}_${2}_${3}.txt'; output_file='plots/${1}_${2}_${3}.png'; xbegin=$4; xend=$5; brief='$1'; main_title='Tarantool $2'" plot.p
}

function gen3 {
    gen2 "$@" && firefox "plots/${1}_${2}_${3}.png";
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

function gen {
    gen2 ping 1.5 hist 19500 20500
    gen2 ping 1.5 cdf 19500 20500
    gen2 insert 1.5 hist 34750 41000
    gen2 insert 1.5 cdf 34750 41000
    gen2 select 1.5 hist 19500 21500
    gen2 select 1.5 cdf 19500 21500
    gen2 delete 1.5 hist 34750 40000
    gen2 delete 1.5 cdf 34750 40000
    gen2 ping 3.0 hist 32570 33570
    gen2 ping 3.0 cdf 32570 33570
    gen2 insert 3.0 hist 49500 54500
    gen2 insert 3.0 cdf 49500 54500
    gen2 delete 3.0 hist 49500 54500
    gen2 delete 3.0 cdf 49500 54500
    gen2 select 3.0 hist 33100 34200
    gen2 select 3.0 cdf 33100 34200
    return
    i=1.5
    j=ping
    i=3.0
    j=delete
}
