
## Простая и компактная библиотека для манипуляций с IPv4 и IPv6-адресами, а так же 48-битными MAC-адресами стандарта Ethernet.

Не использует каких-либо зависимостей, кроме стандартной библиотеки языка **C++17** и **STL**.
Не использует исключений (exceptions). Рассчитана на архитектуру **Intel/AMD x64** и компилятор **GCC**, но с некоторыми доработками будет работать на Visual C++.

Имеется три класса для хранения, обработки и преобразования сетевых адресов :

- **IPv4_Addr**
- **IPv6_Addr**
- **MAC_Addr**

А так же три класса-псевдонима :

- **IPv4_Mask** от IPv4_Addr
- **IPv6_Mask** от IPv6_Addr
- **MAC_Mask** от MAC_Addr

Назначение псевдонимов чисто номинальное : наглядная дифференциация адресов и масок в коде Вашего проекта. Псевдонимы и классы полностью взаимозаменяемы.

Вводятся так же несколько пространств имён для базовых и вспомогательных манипуляций : 
- **v4mnp**
- **v6mnp**
- **macmnp**

Это тоже классы, но наследование от них не имеет большого смысла, т.к. все их методы статические и используются классами IPv4_Addr, IPv6_Addr, и MAC_Addr.

Созданы целые беззнаковые типы с именами в стиле языка Rust : **u8i**, **u16i**, **u32i**, **u64i**, **u128i**, где все, кроме **u128i**, являются псевдонимами соответствующих типов из **cstdint** и имеют более компактную форму записи.

Тип **u128i**  это структура из двух u64i :

    struct u128i {
        u64i ls;
        u64i ms;
    };

Конструкторы классов *IPv4_Addr* (*IPv4_Mask*)
-
    IPv4_Addr(); // будет проинициализировано значением 0.0.0.0
    IPv4_Addr(u32i val); // инициализация целым 32-битным числом (очень быстро)
    IPv4_Addr(u8i oct1, u8i oct2, u8i oct3, u8i oct4); // отдельными октетами
    IPv4_Addr(const u8i arr [4]); // С-массивом из 4 октетов
    IPv4_Addr(const array<u8i,4> &arr); // C++-массивом из 4 октетов
    IPv4_Addr(const string &ipstr); // строковым представлением (очень медленно)

При инициализации из строки всегда происходит валидация синтаксиса, и в случае неудачи объект инициализируется адресом **`u32i(0x0)` 0.0.0.0**. Это наиболее медленный метод.

Напротив, наиболее быстрый (и предпочтительный) - из целого 32-битного числа :

    IPv4_Addr(u32i val);

При инициализации массивом, порядок следования значений - cлева-направо, как в символьном представлении :

    u8i testip[4] {192, 168, 17, 18}; // адрес 192.168.17.18
    IPv4_Addr ip {testip};

Примеры инициализации *IPv4_Addr* (*IPv4_Mask*)
--
**Пустая инициализация адресом 0.0.0.0** :

    IPv4_Addr ip;
    IPv4_Addr ip {}; 
    IPv4_Addr ip = {};

**Целым беззнаковым** :

    IPv4_Addr ip {u32i(0xC0A804FF)}; // 192.168.4.255
    IPv4_Addr ip = {u32i(3232236799)}; // 192.168.4.255
    IPv4_Addr ip {v4mnp::to_u32i("10.1.2.55")}; // 10.1.2.255
    IPv4_Addr ip = {v4mnp::to_u32i("10.1.2.55")}; // 10.1.2.55
    IPv4_Addr ip {v4mnp::UNKNOWN_ADDR}; // 0.0.0.0
    IPv4_Addr ip = {v4mnp::UNKNOWN_ADDR}; // 0.0.0.0

**Строкой** :

    IPv4_Addr ip {"172.17.2.2"}; // 172.17.2.2
    IPv4_Addr ip = {"172.17.2.2"}; // 172.17.2.2

**Отдельными целочисленными октетами** :

    IPv4_Addr ip {198, 51, 100, 177}; // 198.51.100.177
    IPv4_Addr ip = {198, 51, 100, 177}; // 198.51.100.177

**Байтовым массивом из 4 элементов (массив в стиле Си)**  :

    u8i ip_arr[4] {203, 0, 113, 7};
    IPv4_Addr ip {ip_arr}; // 203.0.113.7
    IPv4_Addr ip = {ip_arr}; // 203.0.113.7

**Байтовым массивом из 4 элементов (массив в стиле Си++)** :

    array<u8i,4> arr = {192, 168, 4, 255};
    IPv4_Addr ip {arr}; // 192.168.4.255
    IPv4_Addr ip = {arr}; // 192.168.4.255

**Объектом того же класса** :

    IPv4_Addr ip {IPv4_Addr{0xFFFF, 0xFFFF}}; // 255.255.255.255
    IPv4_Addr ip {v4mnp::to_IPv4("192.0.2.9")}; // 192.0.2.9
    IPv4_Addr ip = v4mnp::to_IPv4("192.0.2.9"); // 192.0.2.9

Методы класса *IPv4_Addr* (*IPv4_Mask*)
--
Внутреннее представление адреса целочисленно, поэтому сохранены следующие операторы :

 \+ - ++ -- += -= << >> <<= >>= & &= | |= > < >= <= == != ~ % /

Можно применять их как между объектами класса IPv4_Addr, так и между объектами IPv4_Addr и u32i.

Метод **`IPv4_Addr::to_str()`** возвращает строковое представление адреса.

**Примеры использования** :

    u32i bitmask = 0xFFFFFF00;
    IPv4_Addr ip {"192.168.4.255"};
    IPv4_Mask mask {bitmask}; // 255.255.255.0
    cout << (ip & mask).to_str() << endl;
    cout << (ip & bitmask).to_str() << endl;

Результат :  
192.168.4.0  
192.168.4.0  

Следующие методы служат для проверки IPv4-адреса на соответствие одному (или нескольким) диапазонам, описанным в документах **RFC** :

    is_unknown(); // 0.0.0.0/32
    is_this_host(); // aka "This host on this network" - RFC 1112
    is_private(); // 10/8, 192.168/16, 172.(16-31)/16 - RFC 1918
    is_loopback(); // 127/8 - RFC 1122
    is_link_local(); // 169.254/16 - RFC 3927
    is_lim_bcast(); // 255.255.255.255/32 - RFC 6890
    is_mcast(); // 224/4 - RFC 5771
    is_ssm_blk(); // 232/8 - RFC 4607
    is_lan_cblock(); // 224.0.0/24 - Local Network Control Block - RFC 5771
    is_inter_cblock(); // 224.0.1/24 - Internetwork Control Block - RFC 5771
    is_adhoc_blk1(); // 224.0.2/24-224.0.255/24 - AD-HOC Block 1 - RFC 5771
    is_adhoc_blk2(); // 224.3/16-224.4/16 - AD-HOC Block II - RFC 5771
    is_adhoc_blk3(); // 233.252/14-233.255/14 - AD-HOC Block III - RFC 5771
    is_sdp_sap(); // 224.2/16 - SDP/SAP Block - RFC 5771
    is_glop_blk(); // 233.0/16-233.251/16 - RFC 5771
    is_adm_scp_blk(); // 239/8 - Administratively Scoped Block - RFC 5771
    is_ubm(); // 234/8 - Unicast-Prefix-Based Multicast - RFC 6034
    is_ucast(); // Unicast
    is_as112(); // 192.31.196/24 - RFC 7535
    is_global_ucast(); // Globally routed unicast
    is_shared(); // 100.64/10 - RFC 6598
    is_reserved(); // 240/4 - RFC 6890
    is_docum(); // 192.0.2/24, 198.51.100/24, 203.0.113/24 - RFC 5737
    is_benchm(); // 198.18/15 - RFC 2544
    is_ietf(); // 192/24 - RFC 6890
    is_dslite(); // 192/29 - RFC 6333, RFC 7335
    is_amt(); // 92.52.193/24 - RFC 7450
    is_dirdeleg(); // 192.175.48/24 - RFC 7534

Каждый из них возвращает значение **bool**.

Поддерживается прямой доступ к целочисленному значению через переменную-член **`IPv4_Addr::as_u32i`** :

    IPv4_Addr ip;
    ip.as_u32i = 0xC0A804FF;
    cout << ip.to_str() << endl;

Результат :  
192.168.4.255  

Для возврата целочисленного представления рекомендуется использовать более компактный способ - через вызов объекта подобно вызову функции :

    IPv4_Addr ip {0xC0A804FF};
    cout << ip() << endl;

Результат :
3232236799  

Прямой доступ на запись и чтение к отдельным октетам через массив **`IPv4_Addr::as_u8i`** возможен, но **является опасным!** Неверная индексация операции присваивания приведёт к выходу за пределы массива, что может вызвать UB. Скорее всего, в окончательной версии этот способ будет удалён, поэтому его не рекомендуется использовать уже сейчас.

На платформе **Intel/AMD x86-x64** очерёдность расположения октетов в памяти реверсивна относительно передачи по линиям связи, поэтому доступ правильнее выполнять, используя константы **`v4mnp::oct1, v4mnp::oct2, v4mnp::oct3, v4mnp::oct4`** в качестве индекса массива.

Более **предпочтителен** метод индексации через **квадратные скобки** к имени объекта. При выходе за пределы массива, будет возвращён 0 либо случайное число, поэтому такой **метод является безопасным**.

    IPv4_Addr ip {192, 168, 4, 255};
    cout << u32i(ip[v4mnp::oct1]) << endl; // соответствует ip.as_u8i[3]
    cout << u32i(ip[v4mnp::oct2]) << endl; // соответствует ip.as_u8i[2]
    cout << u32i(ip[v4mnp::oct3]) << endl; // соответствует ip.as_u8i[1]
    cout << u32i(ip[v4mnp::oct4]) << endl; // соответствует ip.as_u8i[0]
    cout << u32i(ip[13]) << endl; // выход за пределы массива ip.as_u8i !!!
    
Результат :
192
168
4
255
0

    IPv4_Addr ip {192, 168, 4, 255};
    ip[9000] = 150; // ничего не произойдёт, число запишется в специальную "мусорную" переменную
    cout << ip.to_str() << endl;
    
Результат :
192.168.4.255
\
\
Инициализация объекта **IPv4_Mask** происходит аналогично IPv4_Addr. Кроме того существует специальный метод **`v4mnp::gen_mask(u32i mask_len)`**, возвращающий объект IPv4_Mask по указанной длине маски.

Пример :

    IPv4_Mask mask {v4mnp::gen_mask(17)};
    cout << mask.to_str() << endl;

Результат :  
255.255.128.0

Дополнительные методы класса *IPv4_Addr* (*IPv4_Mask*)
--
**Возвращает байтовый массив из 4 элементов в порядке, который соответствует среде передачи данных (старшие октеты передаются первыми)** :

    array<u8i,4> to_media_tx()

**Проверка на чётность и нечётность** :

    bool is_even(); // чётный?
    bool is_odd(); // нечётный?
    
 **Представляет ли адрес корректную маску** :

     bool can_be_mask();

Критерий корректности - непрерывность двоичных единиц слева.

Методы класса *v4mnp*
--
**Валидатор адреса из строки** :

    bool valid_addr(const string &ipstr, IPv4_Addr *ret = nullptr)

Возвращает **true**, если символьный адрес правильный. 
В метод можно передать указатель на переменную IPv4_Addr, куда вернётся сконвертированное значение. Если метод возвращает **false**, то в переменную всегда записывается **`u32i(0x0)` 0.0.0.0**.

**Валидатор маски из строки** :

    bool valid_mask(const string &maskstr, IPv4_Mask *ret = nullptr)

Инвертированные маски, т.н. **wildcard**, в этом методе проверку не пройдут, но для них можно использовать **`v4mnp::valid_addr()`**.

**Конвертор из символьного адреса в целочисленный** :

    u32i to_u32i(const string &ipstr)

При некорректном адресе всегда возвращается **`u32i(0x0)` 0.0.0.0** 

**Конвертор из символьного адреса в объект IPv4_Addr** :

    IPv4_Addr to_IPv4(const string &ipstr)

При некорректном адресе вернёт объект, проинициализированный значением **`u32i(0x0)` 0.0.0.0**.

**Подсчёт длины маски** :

    u32i mask_len(u32i bitmask)

**Не производит валидацию на непрерывность**, подсчитывает только крайние правые нули до первой двоичной единицы .

**По заданной длине генерирует битовую маску** :

    IPv4_Mask gen_mask(u32i mask_len)

## Конструкторы классов *IPv6_Addr* (*IPv6_Mask*)

    IPv6_Addr();
    IPv6_Addr(u64i left, u64i right);
    IPv6_Addr(u64i left, u64i right, bool flag_show_ipv4); // исп-ся для масок IPv6_Mask
    IPv6_Addr(u128i ip);
    IPv6_Addr(u16i xtt1, u16i xtt2, u16i xtt3, u16i xtt4, u16i xtt5, u16i xtt6, u16i xtt7, u16i xtt8);
    IPv6_Addr(const u16i arr[8]);
    IPv6_Addr(const array<u16i,8> &arr);
    IPv6_Addr(const string &ipstr);

При инициализации из строки всегда происходит валидация синтаксиса, и в случае неудачи объект инициализируется адресом **`{0x0, 0x0}` [::]**. Это наиболее медленный метод инициализации.

Напротив, наиболее быстрые (и предпочтительные) методы :

    IPv6_Addr(u64i left, u64i right);
    IPv6_Addr(u128i ip);

При инициализации массивом, порядок следования значений - cлева-направо, как в символьном представлении :

    u16i arr[8] {0x2001, 0xdb8, 0x0, 0x0, 0x0, 0x0, 0xffff, 0xffff};
    IPv6_Addr ip {arr}; // 2001:db8::ffff:ffff

Примеры инициализации *IPv6_Addr* (*IPv6_Mask*):
-
**Пустая инициализация адресом [::]** :

    IPv6_Addr ip;
    IPv6_Addr ip {};
    IPv6_Addr ip = {};
    
**Структурой типа u128i** :

    u128i _128bits {0x20010db800000000, 0x0};
    IPv6_Addr ip {_128bits}; // 2001:db8::

**Двумя целыми беззнаковыми типа u64i** :

    IPv6_Addr ip {0x20010db800000000, 0x0}; // 2001:db8::
    IPv6_Addr ip = {0x20010db800000000, 0x0}; // 2001:db8::
    IPv6_Addr ip = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000, false}; // ffff:ffff:ffff:ffff:ffff:ffff::

Для объектов класса **IPv6_Mask** флаг **flag_show_ipv4** очень важно выставлять в **false**  - это гарантирует правильное отображение при конвертации в string. В ином случае все маски с **0xFFFF** в **6-м хекстете** расцениваются, как IPv6-адреса, имеющие **интегрированый IPv4 (RFC 4291)**.

**Отдельными хекстетами** :

    IPv6_Addr ip {0x2001, 0xdb8, 0x0, 0x0, 0x0, 0x0, 0xffff, 0xffff};
    IPv6_Addr ip = {0x2001, 0xdb8, 0x0, 0x0, 0x0, 0x0, 0xffff, 0xffff};

**Массивом хекстетов (массив в стиле Си)** :

    u16i arr[8] {0x2001, 0xdb8, 0x0, 0x0, 0x0, 0x0, 0xffff, 0xffff};
    IPv6_Addr ip {arr};
    IPv6_Addr ip = {arr};

**Массивом хекстетов (массив в стиле Си++)** :

    array<u16i,8> arr {0x2001, 0xdb8, 0x0, 0x0, 0x0, 0x0, 0xffff, 0xffff};
    IPv6_Addr ip {arr};
    IPv6_Addr ip = {arr};

**Строкой** :

    IPv6_Addr ip {"2001:db8::"};
    IPv6_Addr ip = {"2001:db8::ffff:192.168.10.1"};
    
   При неверном формате будет проинициализарованно адресом **[::]** .
    
  **Объектом того же класса** :

    IPv6_Addr ip {IPv6_Addr{"2001:db8::"}};

Методы класса *IPv6_Addr* (*IPv6_Mask*)
--
Подобно IPv4_Addr, внутреннее представление адреса IPv6_Addr целочисленно, поэтому для класса так же сохранены многие арифметические, битовые и операции сравнения :
 
 \+ - ++ -- += -= << >> <<= >>= & &= | |= > < >= <= == != ~
 
Операторы можно применять только между объектами IPv6_Addr.

Метод **`IPv6_Addr::to_str()`** возвращает строковое представление адреса в формате по умолчанию, но можно отобразить адрес в более специфичном виде через **`IPv6_Addr::to_str(u32i fmt)`**.

Выставление формата по умолчанию происходит через метод **`v6mnp::set_fmt(u32i fmt)`**. Рекомендуется вызывать его один раз в начале Вашей программы. Узнать текущий формат по умолчанию можно через **`v6mnp::what_fmt()`**.

Переменная **fmt** это битовая маска, собранная методом арифметического (либо двоичного) суммирования следующих констант :

- v6mnp::**IETF** = 0 // нижний регистр символов, сворачивание повторяющейся группы нулей, начальные нули хекстета не отображаются
- v6mnp::**Upper** = 1 // переключение на верхний регистр
- v6mnp::**LeadZrs** = 2 // включение отображения начальных нулей
- v6mnp::**Expand** = 4 // разворачивание повторяющейся нулевой группы
- v6mnp::**Full** = 7 // всё это вместе

*Где Full это сумма "Upper + LeadZrs + Expand". Начальным значением при запуске программы будет **0 (IETF)**.*

**Примеры использования** :

    IPv6_Addr ip {0x2001, 0xdb8, 0x0, 0x0, 0x0, 0x0, 0xffff, 0xffff};
    cout << "[1] " << ip.to_str() << endl;
    cout << "[2] " << ip.to_str(v6mnp::IETF) << endl;
    cout << "[3] " << ip.to_str(v6mnp::LeadZrs) << endl;
    cout << "[4] " << ip.to_str(v6mnp::Upper) << endl;
    cout << "[5] " << ip.to_str(v6mnp::Expand) << endl;
    cout << "[6] " << ip.to_str(v6mnp::LeadZrs + v6mnp::Upper) << endl;
    cout << "[7] " << ip.to_str(v6mnp::LeadZrs + v6mnp::Upper + v6mnp::Expand) << endl;
    cout << "[8] " << ip.to_str(v6mnp::Full) << endl;
    v6mnp::set_fmt(v6mnp::Expand);
    cout << "[9] " << ip.to_str() << endl;

Результат :  
[1] 2001:db8::ffff:ffff  
[2] 2001:db8::ffff:ffff  
[3] 2001:0db8::ffff:ffff  
[4] 2001:DB8::FFFF:FFFF  
[5] 2001:db8:0:0:0:0:ffff:ffff  
[6] 2001:0DB8::FFFF:FFFF  
[7] 2001:0DB8:0000:0000:0000:0000:FFFF:FFFF  
[8] 2001:0DB8:0000:0000:0000:0000:FFFF:FFFF  
[9] 2001:db8:0:0:0:0:ffff:ffff  

Следующие методы служат для проверки адреса на соответствие одному (или нескольким) диапазонам, описанным в документах **RFC** :

    is_unspec() // ::1/128 - RFC 4291
    is_loopback() // ::/128 - RFC 4291
    is_glob_ucast() // 2000::/3 - RFC 3513
    is_mcast() // ff00::/8 - RFC 3513
    is_uniq_local() // fc00::/7 - RFC 4193
    is_link_local() // fe80::/10 - RFC 4862
    is_mapped_ipv4() // ::ffff:0:0/96 - RFC 4291
    is_wknown_pfx() // 64:ff9b::/96 - RFC 6052
    is_lu_trans() // 64:ff9b:1::/48  - RFC 8215
    is_ietf() // 2001:0::/23 - RFC2928
    is_teredo() // 2001:0::/32 - RFC4380
    is_benchm() // 2001:2::/48  - RFC 5180
    is_amt() // 2001:3::/32 - RFC 7450
    is_as112() // 2001:4:112::/48 - RFC 7535
    is_orchv2() // 2001:20::/28 - RFC 7343
    is_docum() // 2001:db8::/32 - RFC 3849
    is_6to4() // 2002::/16 - RFC 3056

Возвращают значение **bool**.
	
Подобно IPv4_Addr, класс IPv6_Addr поддерживает прямой доступ к своему целочисленному значению через структуру типа **union**. Хранение **128-битного** значения в памяти требует обратного порядка следования октетов, что нужно учитывать при прямом доступе.

    union {
	       u128i as_u128i;
           u64i  as_u64i[2]; // [1] - левая часть адреса, [0] - правая часть адреса
           u32i  as_u32i[4]; // аналогично, нумерация слева направо [3] [2] [1] [0]
           u16i  as_u16i[8]; // аналогичный принцип [7] [6] [5] ... [1] [0]
           u8i   as_u8i[16]; // аналогичный принцип [15] [14] [13] ... [1] [0]
    };

Как и в случае IPv4_Addr, способ **прямой индексации массивов является небезопасным** и в будуших версиях скорее всего будет удалён.

Более **предпочтителен** метод индексации через **квадратные скобки**, применённые к объекту. При выходе за пределы массива возвращается 0 либо случайное число, поэтому такой **метод является безопасным**.

На платформе **Intel/AMD x86-x64** очерёдность расположения хекстетов в памяти (и байтов в отдельно взятом хекстете)  реверсивна относительно передачи по линиям связи, поэтому доступ правильнее выполнять, используя константы **`v6mnp::xtt1 - v6mnp::xtt8`** в качестве индекса массива :

    IPv6_Addr ip {0x20010db8ffff0000, 0x1000200030004};
    cout << ip[v6mnp::xtt1] << endl; // соответствует ip.as_u16i[7]
    cout << ip[v6mnp::xtt2] << endl; // соответствует ip.as_u16i[6]
    cout << ip[v6mnp::xtt3] << endl; // соответствует ip.as_u16i[5]
    cout << ip[v6mnp::xtt4] << endl; // соответствует ip.as_u16i[4]
    cout << ip[v6mnp::xtt5] << endl; // соответствует ip.as_u16i[3]
    cout << ip[v6mnp::xtt6] << endl; // соответствует ip.as_u16i[2]
    cout << ip[v6mnp::xtt7] << endl; // соответствует ip.as_u16i[1]
    cout << ip[v6mnp::xtt8] << endl; // соответствует ip.as_u16i[0]
    cout << "garbage at index [13] = " << ip[13] << endl; // выход за пределы массива ip.as_u16i !!!

Результат :  
8193  
3512  
65535  
0  
1  
2  
3  
4  
garbage at index [13] = 0  

    IPv6_Addr ip {0x20010db8ffff0000, 0x1000200030004};
    ip[13] = 9; // ничего не произойдёт, число запишется в специальную "мусорную" переменную
    cout << ip.to_str() << endl;
    
Результат :  
2001:db8:ffff:0:1:2:3:4  

Дополнительные методы класса *IPv6_Addr* (*IPv6_Mask*)
-
**Возвращает байтовый массив из 16 элементов (128 бит) в порядке, который соответствует среде передачи данных (старшие октеты передаются первыми)** :

    array<u8i,16> to_media_tx()

**Интегрирует адрес IPv4 внутрь адреса IPv6 в соотв. с RFC 4291** :

    map_ipv4(u32i ipv4);
    map_ipv4(IPv4_Addr ipv4);

**Снимает и поднимает флаг отображения интегрированного ipv4** :

    unsetflag_show_ipv4();
    setflag_show_ipv4();

Если Вы сгенерировали маску не с помощью **`v6mnp::gen_mask()`**, а иным способом, то для правильного отображения необходимо вызвать **`IPv6_Addr::unsetflag_show_ipv4()`**. Метод **`IPv6_Addr::setflag_show_ipv4()`** возвращает поведение по умолчанию, когда флаг в состоянии **true**. Для адресов метод **`IPv6_Addr::setflag_show_ipv4()`** вызывать не требуется. 

**Проверка на чётность и нечётность** :

    bool is_even(); // чётный?
    bool is_odd(); // нечётный?
    
 **Представляет ли адрес корректную маску** :

     bool can_be_mask();

Критерий корректности - непрерывность двоичных единиц слева.

Методы класса *v6mnp* :
-
**Валидатор адреса из строки**  :

    bool valid_addr(const string &ipstr, IPv6_Addr *ret = nullptr)

Возвращает **true**, если символьный адрес синтаксически верен.
В метод можно передать указатель на переменную IPv6_Addr, куда вернётся сконвертированное значение. Если метод возвращает **false**, то в переменную всегда записывается **`{0x0, 0x0}` [::]**.

**Конвертор из символьного адреса в объект IPv6_Addr** :

    IPv6_Addr to_IPv6(const string &ipstr)

При некорректном адресе вернёт объект, проинициализированный значением  **`{0x0, 0x0}` [::]**.

**По заданной длине генерирует битовую маску** :

    IPv6_Mask gen_mask(u32i mask_len)
    
**Подсчёт длины маски** :

    u32i mask_len(const IPv6_Mask &mask)

**Не производит валидацию на непрерывность**, подсчитывает только крайние правые нули до первой двоичной единицы .

**Возвращает link-local адрес, созданный из interface_id** :

    IPv6_Addr gen_link_local(u64i iface_id)

**Возвращает link-local адрес, созданный из MAC-адреса** :

    IPv6_Addr gen_link_local(const MAC_Addr &mac)

**Устанавливает формат по умолчанию для представления адреса в текстовом виде** :

    set_fmt(u32i fmt)

**Возвращает текущий формат по умолчания для представления адреса в текстовом виде** :

    u32i what_fmt()

Конструкторы класса *MAC_Addr* :
-

    MAC_Addr(); // будет проинициализированно значением u64i(0) 00:00:00:00:00:00
    MAC_Addr(u64i _48bits); // целочисленным значением, старшие два байта u64i не учитываются и будут обнулены
    MAC_Addr(u32i oui, u32i nic); // иниц-я через значения OUI и NIC, старший байт обоих значений не учитывается и будет обнулён
    MAC_Addr(const string &macstr, char sep, u32i grp_len); // через строку с указанным форматом
	MAC_Addr(const string &macstr); // через строку в формате по умолчанию

Конструктор из строки производит валидацию с использованием указанного символа-разделителя **sep** и количества байтов **grp_len** (не более 3) в одной группе. Если строка не будет соответствовать формату, то объект проинициализируется нулём **`u64i(0x0)`**.

**Примеры адресов** :

- 38-68-93-80-07-E6   // разделитель "-" и 1 байт в каждой групе, всего 6 групп 
- 38:68:93:80:07:E6   // разделитель ":" и 1 байт в каждой групе, всего 6 групп
- 3868.9380.07E6      // разделитель "." и 2 байта в каждой групе, всего 3 группы

Допускаются 3-байтовые группы, хотя такой формат не имеет примеров использования в реальных системах.

Примеры инициализации *MAC_Addr* :
-
**Пустая инициализация адресом 00:00:00:00:00:00** :

    MAC_Addr mac;
    MAC_Addr mac {}; 
    MAC_Addr mac = {};

**Целым беззнаковым** :

    MAC_Addr mac {0x3868938007E6};

**Левой и правой половинами адреса** :

    MAC_Addr mac {0x386893б 0x8007E6};

**Строкой** :

    MAC_Addr mac {"38-68-93-80-07-E6", '-', 1};
    MAC_Addr mac {"38:68:93:80:07:E6", '-', 1};
    MAC_Addr mac {"3868-9380-07E6", '-', 2};

Внутреннее представление адреса MAC_Addr целочисленно, поэтому сохранены некоторые арифметические, битовые и операции сравнения :   

& &= > < >= <= == != | |= / % 

Операторы можно применять между объектами класса MAC_Addr, а так же между MAC_Addr и целыми типами u64i (**в операциях будут участвовать только 48 бит из 64**).

Методы класса *MAC_Addr* :
-
Метод **`MAC_Addr::to_str()`** возвращает строковое представление адреса в формате по умолчанию, но можно отобразить адрес в более специфичном виде через **`MAC_Addr::to_str(char sep, u32i grp_len, bool caps)`**, куда передаётся символ-разделитель, количество байт в одной группе и флаг регистра символов (большие или малые).

Выставление формата по-умолчанию происходит через метод **`macmnp::set_fmt(char sep, u32i grp_len, bool caps)`**. Рекомендуется вызывать его один раз в начале Вашей программы.

**Узнать текущие настройки по умолчанию позволяют следующие методы** :

    char macmnp::what_sep();
    u32i macmnp::what_grp_len();
    bool macmnp::what_caps();

**Примеры использования** :

    MAC_Addr mac {"38-68-93-80-07-E6", '-', 1};
    cout << "[1] " << mac.to_str() << endl;
    cout << "[2] " << mac.to_str(':', 1 , true) << endl;
    cout << "[3] " << mac.to_str('-', 1 , true) << endl;
    cout << "[4] " << mac.to_str('.', 1 , true) << endl;
    cout << "[5] " << mac.to_str('-', 2 , false) << endl;
    cout << "[6] " << mac.to_str(':', 2 , false) << endl;
    macmnp::set_fmt('.', 2, true);
    cout << "[7] " << mac.to_str() << endl;
	

Результат :  
[1] 38:68:93:80:07:E6  
[2] 38:68:93:80:07:E6  
[3] 38-68-93-80-07-E6  
[4] 38.68.93.80.07.E6  
[5] 3868-9380-07e6  
[6] 3868:9380:07e6  
[7] 3868.9380.07E6  

Следующие методы класса MAC_Addr служат для проверки адреса на соответствие одному (или нескольким) диапазонам, описанным в документах **IEEE802** :

    is_ucast() // unicast
    is_mcast() // multicast
    is_bcast() // broadcast
    is_uaa() // universally administered addresses 
    is_laa() // locally administered addresses

Возвращают значение типа **bool**.

Класс поддерживает прямой доступ к своему целочисленному значению через структуру типа **union**.
Хранение **48**-битного адреса в памяти требует числа **u64i** и обратного порядка следования октетов, что нужно учитывать.

    union {
           u64i as_48bits;
           u8i  as_u8i[8]; 
    };

Здесь есть все те же **опасности**, как и для типов IPv4_Addr, IPv6_Addr. Поэтому, чтобы исключить путаницу и критические ошибки, для индексации были созданы константы **`macmnp::oct1 - oct6`**. Рекомендуется всегда использовать только их и индексировать не массив **`MAC_Addr::as_u8i`**, а сам объект :

    MAC_Addr mac {"38:68:93:80:07:E6", ':', 1};
    cout << u32i(mac[macmnp::oct1]) << endl;
    cout << u32i(mac[macmnp::oct2]) << endl;
    cout << u32i(mac[macmnp::oct3]) << endl;
    cout << u32i(mac[macmnp::oct4]) << endl;
    cout << u32i(mac[macmnp::oct5]) << endl;
    cout << u32i(mac[macmnp::oct6]) << endl;
    cout << u32i(mac[100500]) << endl;
    mac[100500] = 90;
    cout << mac.to_str() << endl;
    
Результат :
104  
147  
128  
7  
230  
0  
38:68:93:80:07:E6  

Для возврата целочисленного значения, вместо обращения к **`MAC_Addr::as_48bits`** можно использовать вызов объекта, подобно функции, с использованием круглых скобок **`MAC_Addr()`**.

**Старшие 2 байта числа `u64i(MAC_Addr::as_48bits)` (и соответствующие октеты `MAC_Addr::as_u8i[7]`, `MAC_Addr::as_u8i[6]`) не используются. Если есть опасения, что прямой доступ привёл к выставлению ненулевых значений, нужно воспользоваться методом `MAC_Addr::fix()`.**

Дополнительные методы класса *MAC_Addr* 
-
**Возвращает  массив из 6 элементов в порядке следования байтов, как в среде передачи данных (старшие октеты передаются первыми)**:

    array<u8i,6> get_media_tx_fmt()

**Выставляет поле NIC** :

    void set_nic(u32i nic)

**Выставляет поле OUI** :

    void set_oui(u32i oui)

**Возвращает NIC** :

    u32i get_nic()

**Возвращает OUI** :

    u32i get_oui()

 **Обнуление старших 2 байтов представления u64i(as_48bits)** :

     void fix()

**Проверка на чётность и нечётность** :

    bool is_even();
    bool is_odd();
     
Доступ через **`MAC_Addr::as_u8i`** и **`MAC_Addr::as_48bits`** позволяет случайно или намеренно выставить ненулевые значения 2 старших байтов. Метод **`MAC_Addr::fix()`** обнуляет данные значения, т.к. они не должны использоваться.


Методы класса *macmnp*
-
**Валидатор MAC-адреса из строки** :

    bool valid_addr(const string &macstr, char sep, u32i grp_len, MAC_Addr *ret = nullptr);
    bool valid_addr(const string &macstr, MAC_Addr *ret = nullptr);
    
Возвращает **true**, если символьный адрес синтаксически верен.
В метод можно передать указатель на переменную MAC_Addr, куда вернётся сконвертированное значение. Если метод возвращает **false**, то в переменную всегда записывается **`u64i{0x0}` [::]**.

**Возврат целочисленного значения MAC-адреса из строки** :

    u64i to_48bits(const string &macstr, char sep, u32i grp_len)
    u64i to_48bits(const string &macstr)

**Возврат объекта MAC_Addr из строки** :

    MAC_Addr to_MAC(const string &macstr, char sep, u32i grp_len)
    MAC_Addr to_MAC(const string &macstr)

**Возврат мультикастного MAC-адреса для IPv4-адреса** :

    MAC_Addr gen_mcast(const IPv4_Addr &ip)

**Возврат мультикастного MAC-адреса для IPv4-адреса** :

    MAC_Addr gen_mcast(const IPv6_Addr &ip);

**Устанавливает формат по умолчанию для строкового представления MAC-адреса** :

    void set_fmt(char sep, u32i grp_len, bool caps)

**Возвращают текущие настройки формата по умолчанию** :

    char what_sep()
    u32i what_grp_len()
    bool what_caps()
