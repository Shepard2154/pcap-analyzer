import csv
import sys
from collections import defaultdict


def process_csv(input_file_path, output_file_path):
    ip_address_stat = defaultdict(
        lambda: {
            "received_packets": 0,
            "received_bytes": 0,
            "sent_packets": 0,
            "sent_bytes": 0,
        }
    )

    with open(input_file_path, mode="r", newline="") as file:
        reader = csv.reader(file)
        next(reader)

        for row in reader:
            src_ip, dst_ip, src_port, dst_port, packets, bytes = row

            ip_address_stat[src_ip]["sent_packets"] += int(packets)
            ip_address_stat[src_ip]["sent_bytes"] += int(bytes)

            ip_address_stat[dst_ip]["received_packets"] += int(packets)
            ip_address_stat[dst_ip]["received_bytes"] += int(bytes)

    with open(output_file_path, mode="w", newline="") as outfile:
        writer = csv.writer(outfile)
        writer.writerow(
            [
                "IP адрес",
                "Кол-во принятых пакетов",
                "Кол-во принятых байт",
                "Кол-во переданных пакетов",
                "Кол-во переданных байт",
            ]
        )

        for ip, data in ip_address_stat.items():
            writer.writerow(
                [
                    ip,
                    data["received_packets"],
                    data["received_bytes"],
                    data["sent_packets"],
                    data["sent_bytes"],
                ]
            )


def main():
    if len(sys.argv) != 3:
        print("Использование: python3 main.py <входной_файл.csv> <выходной_файл.csv>")
        sys.exit(1)

    input_csv = sys.argv[1]
    output_csv = sys.argv[2]

    process_csv(input_csv, output_csv)
    print(f"Обработанные данные сохранены в файл: {output_csv}")

if __name__ == "__main__":
    main()