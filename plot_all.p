print output_file

set title main_title
set grid
set terminal png size 1280,720
set output sprintf('%s', output_file)
set xrange [xbegin:xend]
set key right top

plot input_ping pointtype 7 pointsize 1 title 'ping', \
     input_insert pointtype 7 pointsize 1 title 'insert', \
     input_select pointtype 7 pointsize 1 title 'select', \
     input_delete pointtype 7 pointsize 1 title 'delete'
