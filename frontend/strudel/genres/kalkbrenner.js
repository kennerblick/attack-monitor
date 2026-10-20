// Paul Kalkbrenner: melodischer Berliner Techno um 122–128 BPM. Warme, gerade Kick, rollender
// Offbeat-Bass, hymnische Saw-Leads mit langem Echo, melancholische Moll-Flächen, sparsame Vocal-Chops.
// Varianten lehnen sich im Stil an bekannte Tracks an, Melodien sind eigene.
export default {
  key: "kalkbrenner", name: "Kalkbrenner", color: "#c98500",
  tracks: [
    { key: "kick", label: "Kick", code: 's("bd*4").bank("{B}").lpf(3200).gain(1.05)' },
    { key: "clap", label: "Clap", code: 's("~ cp ~ cp").bank("{B}").room(.35).gain(.5)' },
    { key: "hats", label: "Offbeat-Hat", code: 's("[~ hh]*4").bank("{B}").gain(.35)' },
    { key: "shuffle", label: "16tel-Hats", code: 's("hh*16").bank("{B}").gain("[.16 .07 .12 .07]*4").pan(sine.slow(8))' },
    { key: "perc", label: "Percussion", code: 's("~ ~ rim ~ ~ rim ~ [~ rim]").bank("{B}").gain(.32).delay(.25)' },
    { key: "bass", label: "Rollbass", code: 'n("[~ 0] [~ 0] [~ 3] [~ <0 5>]").scale("{K}1:{S}").s("sawtooth").lpf(380).lpq(4).decay(.18).sustain(0).gain(.75)' },
    { key: "sub", label: "Sub", code: 'n("<0 -2 -3 -4>").scale("{K}1:{S}").s("sine").attack(.05).release(.3).gain(.45)' },
    { key: "lead", label: "Hymnen-Lead", code: 'n("<[0 ~ ~ 2 ~ ~ 4 ~] [3 ~ ~ 2 ~ ~ 0 ~] [0 ~ ~ 2 ~ ~ 4 ~] [5 ~ 4 ~ 2 ~ ~ ~]>").scale("{K}4:{S}").s("sawtooth").lpf(sine.range(1200,3200).slow(16)).decay(.3).sustain(.4).release(.4).gain(.2).delay(.45).delaytime(.375).delayfeedback(.5).room(.4)' },
    { key: "arp", label: "Arpeggio", code: 'n("0 4 7 4 0 4 7 9").scale("{K}3:{S}").s("square").lpf(1600).decay(.1).sustain(0).gain(.15).delay(.3).pan(sine.slow(4))' },
    { key: "pad", label: "Fläche", code: 'n("<[0,2,4] [-2,0,2] [-3,-1,1] [-4,-2,0]>").scale("{K}3:{S}").s("supersaw").attack(1).release(2).lpf(1400).gain(.15).room(.6)' },
    { key: "vox", label: "Vocal-Chop", code: 's("speech:<0 2 4 6>").struct("~ ~ ~ ~ x ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~").speed(.9).lpf(3000).room(.5).delay(.4).gain(.5)' },
    { key: "fx", label: "Riser", code: 's("pink").hpf(saw.range(300,8000).slow(16)).gain(.06).room(.5)' },
  ],
  variants: [
    { key: "skysand", name: "Sky and Sand", bpm: 123, bank: "RolandTR909", scale: "minor", key0: "D",
      desc: "Hymnischer Lead über warmen Flächen, große Melancholie", on: ["kick", "clap", "hats", "bass", "lead", "pad"], tracks: {} },
    { key: "aaron", name: "Aaron", bpm: 124, bank: "RolandTR909", scale: "minor", key0: "A",
      desc: "Düster, rollender Bass, tickende Percussion", on: ["kick", "hats", "shuffle", "perc", "bass", "arp"],
      tracks: {
        bass: 'n("[~ 0] [~ 0] [~ 0] [~ <0 1>]").scale("{K}1:{S}").s("sawtooth").lpf(sine.range(260,520).slow(8)).lpq(10).decay(.15).sustain(0).gain(.8)',
        arp: 'n("0 ~ 3 ~ 0 ~ <5 7> ~").scale("{K}3:{S}").s("square").lpf(1100).decay(.08).sustain(0).gain(.14).delay(.5).delaytime(.375)',
      } },
    { key: "gebruenn", name: "Gebrünn Gebrünn", bpm: 126, bank: "RolandTR909", scale: "phrygian", key0: "E",
      desc: "Verspielter, quengelnder Synth-Hook, treibend", on: ["kick", "clap", "hats", "shuffle", "bass", "arp", "vox"],
      tracks: {
        arp: 'n("0 0 7 0 5 0 3 [2 0]").scale("{K}3:{S}").s("square").lpf(sine.range(600,2400).slow(4)).lpq(8).decay(.12).sustain(0).gain(.2)',
      } },
    { key: "cloud", name: "Cloud Rider", bpm: 122, bank: "RolandTR909", scale: "minor", key0: "G",
      desc: "Weite Flächen, sanftes Arpeggio, Breakdown-Gefühl", on: ["kick", "hats", "sub", "arp", "pad", "vox", "fx"],
      tracks: {
        kick: 's("bd*4").bank("{B}").lpf(1800).gain(.95)',
        arp: 'n("0 2 4 7 9 7 4 2").scale("{K}4:{S}").s("triangle").decay(.15).sustain(0).gain(.18).delay(.5).room(.5)',
      } },
    { key: "kamuffel", name: "Altes Kamuffel", bpm: 125, bank: "RolandTR909", scale: "minor", key0: "C",
      desc: "Minimal, Klicks, trocken (frühe BPitch-Control-Phase)", on: ["kick", "hats", "perc", "bass", "arp"],
      tracks: {
        perc: 's("rim(5,16,3)").bank("{B}").gain(.35).pan(sine.slow(2))',
        bass: 'n("~ 0 ~ ~ ~ 0 ~ <3 2>").scale("{K}1:{S}").s("sine").decay(.15).sustain(0).gain(.9)',
        arp: 'n("0 ~ ~ 7 ~ ~ <3 5> ~").scale("{K}4:{S}").s("sine").decay(.08).sustain(0).gain(.22).delay(.5)',
      } },
    { key: "berlin", name: "Berlin Calling", bpm: 123, bank: "RolandTR909", scale: "minor", key0: "F",
      desc: "Soundtrack-Melancholie: Arpeggio, Streicherfläche, ruhiger Lead", on: ["kick", "hats", "sub", "arp", "pad", "lead"],
      tracks: {
        lead: 'n("<[4 ~ ~ ~ 2 ~ ~ ~] [0 ~ ~ ~ ~ ~ -1 ~]>").scale("{K}4:{S}").s("sawtooth").lpf(1800).attack(.08).release(.8).gain(.17).delay(.5).delaytime(.375).delayfeedback(.55).room(.5)',
      } },
    { key: "liveset", name: "Live-Set Peak", bpm: 128, bank: "RolandTR909", scale: "minor", key0: "A",
      desc: "Volle Energie wie am Ende eines Live-Sets, mit Riser", on: ["kick", "clap", "hats", "shuffle", "perc", "bass", "lead", "pad", "fx"],
      tracks: {} },
  ],
};
