print output_file

set title main_title
set grid
set terminal png size 1024,768
set output sprintf('%s', output_file)
set xrange [xbegin/1000.0:xend/1000.0]
set xlabel sprintf('%s', x_label)
set ylabel sprintf('%s', y_label)
set key left top

plot input_file using ($1/1000.0):($2) pointtype 7 pointsize 1 title brief
