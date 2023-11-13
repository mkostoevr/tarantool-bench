print output_file

set title main_title
set grid
set terminal png size 1280,720
set output sprintf('%s', output_file)
set xrange [xbegin:xend]
set yrange [ybegin/1000.0:yend/1000.0]
set xlabel sprintf('%s', x_label)
set ylabel sprintf('%s', y_label)
set key right top

plot input_a using ($1):($2/1000.0) pointtype 7 pointsize 1 title brief_a, \
     input_b using ($1):($2/1000.0) pointtype 7 pointsize 1 title brief_b
