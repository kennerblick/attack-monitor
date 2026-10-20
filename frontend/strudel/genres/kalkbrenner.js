// Paul Kalkbrenner: melodischer Berliner Techno um 122–128 BPM. Warme, gerade Kick, rollender
// Offbeat-Bass, hymnische Saw-Leads mit langem Echo, melancholische Moll-Flächen, sparsame Vocal-Chops.
// Varianten lehnen sich im Stil an bekannte Tracks an, Melodien sind eigene.
// Klang: Synths mit Filterhüllkurve (lpenv), Supersaw mit Unison/Detune, Samples gefiltert und gesättigt,
// damit es nicht nach Preset klingt – das ist der Kern des Kalkbrenner-Sounds.
export default {
  key: "kalkbrenner", name: "Kalkbrenner", color: "#c98500",
  tracks: [
    { key: "kick", label: "Kick", code: 's("bd*4").bank("{B}").lpf(3200).shape(.15).gain(1)' },
    { key: "clap", label: "Clap", code: 's("~ cp ~ cp").bank("{B}").hpf(350).room(.35).roomsize(2).gain(.5)' },
    { key: "hats", label: "Offbeat-Hat", code: 's("[~ hh]*4").bank("{B}").hpf(7000).gain(.4)' },
    { key: "shuffle", label: "16tel-Hats", code: 's("hh*16").bank("{B}").gain("[.16 .07 .12 .07]*4").pan(sine.slow(8))' },
    { key: "perc", label: "Percussion", code: 's("~ ~ rim ~ ~ rim ~ [~ rim]").bank("{B}").gain(.32).delay(.25)' },
    { key: "bass", label: "Rollbass", code: 'n("[~ 0] [~ 0] [~ 3] [~ <0 5>]").scale("{K}1:{S}").s("sawtooth").lpf(240).lpenv(3).lpd(.12).lpq(6).decay(.18).sustain(0).shape(.2).gain(.7)' },
    { key: "sub", label: "Sub", code: 'n("<0 -2 -3 -4>").scale("{K}1:{S}").s("sine").attack(.05).release(.3).gain(.45)' },
    { key: "lead", label: "Hymnen-Lead", code: 'n("<[0 ~ ~ 2 ~ ~ 4 ~] [3 ~ ~ 2 ~ ~ 0 ~] [0 ~ ~ 2 ~ ~ 4 ~] [5 ~ 4 ~ 2 ~ ~ ~]>").scale("{K}4:{S}").s("supersaw").unison(5).detune(.22).spread(.7).lpf(sine.range(1200,3200).slow(16)).lpenv(1.5).lpd(.25).decay(.3).sustain(.4).release(.4).gain(.16).delay(.45).delaytime(.375).delayfeedback(.5).room(.4)' },
    { key: "arp", label: "Arpeggio", code: 'n("0 4 7 4 0 4 7 9").scale("{K}3:{S}").s("square").lpf(900).lpenv(2.5).lpd(.08).decay(.1).sustain(0).gain(.15).delay(.3).pan(sine.slow(4))' },
    { key: "pad", label: "Fläche", code: 'n("<[0,2,4] [-2,0,2] [-3,-1,1] [-4,-2,0]>").scale("{K}3:{S}").s("supersaw").unison(7).detune(.3).spread(.9).attack(1.2).release(2.5).lpf(sine.range(900,1800).slow(32)).gain(.13).room(.7).roomsize(6)' },
    { key: "vox", label: "Vocal-Chop", code: 's("speech:<0 2 4 6>").struct("~ ~ ~ ~ x ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~").speed(.9).hpf(250).lpf(3000).room(.5).delay(.4).gain(.5)' },
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
    { key: "train", name: "Train", bpm: 124, bank: "RolandTR909", scale: "minor", key0: "A",
      desc: "Ratternder 16tel-Bass wie Schienenstöße, euphorischer Riff, nach vorn", on: ["kick", "clap", "hats", "shuffle", "perc", "bass", "lead", "pad"],
      tracks: {
        shuffle: 's("hh*16").bank("{B}").hpf(8000).gain("[.18 .06 .1 .06]*4").pan(sine.slow(2))',
        perc: 's("~ ~ ~ ~ ~ ~ rim ~ ~ ~ ~ ~ rim ~ rim ~").bank("{B}").hpf(1500).gain(.3).delay(.2)',
        bass: 'n("0*16").scale("{K}1:{S}").s("sawtooth").gain("[.75 .4 .55 .4]*4").lpf(200).lpenv(2.5).lpd(.06).lpq(8).decay(.08).sustain(0).shape(.25)',
        lead: 'n("<[0 ~ 2 4 ~ 4 ~ 7] [6 ~ 4 ~ 2 ~ 4 ~] [0 ~ 2 4 ~ 4 ~ 7] [9 ~ 7 ~ 4 ~ 2 ~]>").scale("{K}4:{S}").s("supersaw").unison(5).detune(.25).spread(.7).lpf(sine.range(1400,3600).slow(8)).lpenv(2).lpd(.15).decay(.2).sustain(.3).release(.3).gain(.15).delay(.35).delaytime(.1875).delayfeedback(.4).room(.4)',
      } },
    { key: "feedhead", name: "Feed Your Head", bpm: 123, bank: "RolandTR909", scale: "dorian", key0: "D",
      desc: "Psychedelisch, Vocal-Chops im Delay, schwebende Orgelfläche", on: ["kick", "clap", "hats", "bass", "sub", "arp", "pad", "vox", "fx"],
      tracks: {
        bass: 'n("[~ 0] [~ 0 0 ~] [~ 0] [~ <3 5>]").scale("{K}1:{S}").s("sawtooth").lpf(sine.range(180,420).slow(16)).lpenv(2).lpd(.1).lpq(10).decay(.15).sustain(0).shape(.2).gain(.7)',
        arp: 'n("<[0 4 7 4]*2 [2 5 9 5]*2>").scale("{K}3:{S}").s("triangle").fm(1.5).fmh(2).decay(.12).sustain(0).gain(.16).delay(.5).delaytime(.375).delayfeedback(.6).pan(sine.slow(8))',
        pad: 'n("<[0,2,4,6] [1,3,5,7]>/2").scale("{K}3:{S}").s("sine").fm(.8).fmh(3).attack(1.5).release(3).gain(.16).phaser(.25).room(.8).roomsize(8)',
        vox: 's("speech:<1 3 5 7>").struct("~ ~ ~ ~ x ~ ~ ~ ~ ~ ~ x ~ ~ ~ ~").speed("<.8 .85>").hpf(300).lpf(2800).vowel("<o a>").room(.6).delay(.55).delaytime(.375).delayfeedback(.55).gain(.55)',
      } },
  ],
};
