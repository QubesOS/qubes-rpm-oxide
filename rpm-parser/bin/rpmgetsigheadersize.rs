use rpm_parser;

fn main() {
    let mut args = std::env::args_os();
    if args.next().is_none() {
        panic!("argv[0] is NULL");
    };
    for i in args {
        let mut s = std::fs::File::open(i).expect("cannot open input file");
        rpm_parser::read_lead(&mut s).expect("bad input file");
        let (index_size, data_size) = rpm_parser::read_header_magic(&mut s).unwrap();
        println!(
            "Signature header index size is {}, data size is {}, offset is 96, size is {}",
            index_size,
            data_size,
            16 * (index_size + 1) + data_size
        );
    }
}
