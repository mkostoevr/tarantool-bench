box.cfg{
    listen = 3301,
}

s = box.schema.space.create('s')
s:create_index('pk')

function bench_call() end
function bench_insert(id) s:insert({id}) end
function bench_replace(id) s:replace({id}) end
function bench_select(id) s:select({id}) end
function bench_delete(id) s:delete({id}) end

box.schema.user.grant('guest','read,write,execute,create,drop','universe')
