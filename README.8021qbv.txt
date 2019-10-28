This archive contains a demonstration of 802.1Qbv on the NXP LS1028A-RDB board.
It covers both the standalone ENETC port as well as the Felix switch ports.

It is being developed and tested on the openil 1.6-community rootfs image
(https://github.com/vladimiroltean/openil-community), but it likely to be able
to run on other distributions as well.

Copy this folder to the home directory of the root user on two boards and run
as follows:

[user@pc]# for board in 10.0.0.101 10.0.0.102 103; do rsync -avr ./ root@${board}:tsn-scripts/; done

Hint:
The openil-community images have a command called "passwordless-ssh-login"
which can simplify the SSH login process, at the expense of insecurity by
default. Use at your own risk.

[root@board1]# ./tsn-scripts/time-test 1 prepare
[root@board2]# ./tsn-scripts/time-test 2 prepare
[root@board1]# ./tsn-scripts/time-test 1 run

Optional:

[root@board3]# ./time-test.sh 3 prepare

A Qbv latency report will be generated.

Systemd services for the linuxptp package suite will be installed on the target
board during the "prepare" phase. Be aware of this as they might overwrite
other such services (although NXP rootfs images do not provide them by
default).

To change the scenario between ENETC and Felix, you need to edit the "scenario"
Bash variable from time-test.sh.

For cabling and further information, see the comments inside time-test.sh.

 base-time                         base-time + cycle-time
|---------------------------------|---------------------------------|

Ethernet media reservation:

|xxxxxxxxxxxxxxxxxxxxxxx|---------|xxxxxxxxxxxxxxxxxxxxxxx|---------| tc012346
 <--------------------->           <--------------------->
 best effort                       best effort

|-----------------------|xxxx|----|-----------------------|xxxx|----| tc7
                         <-->                              <-->
                         ptp4l                             ptp4l

|----------------------------|xxxx|----------------------------|xxxx| tc5
                              <-->                              <-->
                           raw-l2-send                       raw-l2-send


Concentrating on a single time slot (raw-l2-send), let's overlap a few
timelines to understand where the time is spent:

cycle (N - 1)                     cycle N
base-time - cycle-time            base-time
|                                 |                 advance-time
|                                 |              <--------------
|                                 |                   shift-time
|                                 | --------------------------->
|                            T0 T1|                      media reservation
v                            <--->v                             <--->
|-------------|xxxxxxxxx|---------|-------------|xxxxxxxxx|---------| App CPU
              t0        t1                      t7        t8          time 1

|-----------------------|xx|------|-----------------------|xx|------| Kernel CPU
                        t1 t2                                         time 1

|--------------------------|xxxx|-|--------------------------|xxxx|-| MAC time
                           t2   t3

|--------------------------------|xxx|------------------------------| Kernel CPU
                                 t4  t5                               time 2

|---------------------------------|--|xx|---------------------------| App CPU
                                     t5 t6                            time 2

The reason why raw-l2-send is scheduled yet once more, after the frame
transmission has occured, is to collect the TX timestamp and print the log
message. This is its non-critical portion.

Where:
t0, t7: wakeup times for the raw-l2-send user space process
t1: hand-over times between raw-l2-send process and kernel stack (i.e.
    approximately socket enqueue time). Afterwards, the NET_TX softirq
    schedules transmission of the frame.
t2: hand-over time between kernel driver and hardware. Approximated by
    the software TX timestamp of the frame. Also the time at which the
    Ethernet controller starts the frame's DMA transfer and prepares it
    for transmission.
t3: the frame transmission is complete and the MAC TX timestamp is available.
t4: kernel processes the TX timestamp and enqueues it back towards the
    application socket.
t5: second wakeup time for the raw-l2-send application, to collect the
    hardware and software TX timestamps.
t6: the user space application calls clock_nanosleep() again
T0: MAC gate open events for cyclic scheduled traffic
T1: MAC gate close events

The problem's deadline can be expressed as:
t3 < T1

At this time let's introduce the raw-l2-send command line arguments:

--cycle-time: The length of the MAC schedule in nanoseconds. Also the period
              of the raw-l2-send process.
--base-time: The base time of the MAC schedule, transposed to CLOCK_REALTIME
             (minus UTC offset).
--shift-time: The offset of its time slot within the schedule. Must be
              positive. This is the same as the value of T0 relative to
              cycle N.
--advance-time: The offset of the program's wakeup time, relative to its time
                slot. It is a positive value with a negative meaning. So its
                value can be described as (T0 - t0), in the absolutely ideal
                case that the process is woken up and scheduled on the run
                queue right away. The trigger for the process wakeup will
                always be at:

                base-time + shift-time + (N * cycle-time) - advance-time.
