// Jean-Michel Jarre: Elektronik der späten 70er/80er, 100–125 BPM. Weiche Rhythmusbox (Korg Minipops),
// Sequencer-Bass in 16teln, schwebende String-Machine mit Phaser, singende Leads mit Vibrato, Wind- und
// Meeresrauschen, Laserharfe. Varianten lehnen sich im Stil an bekannte Stücke an, Melodien sind eigene.
// Klang: Phaser und langsame Filterfahrten machen den analogen Charakter; Drums leise und trocken.
export default {
  key: "jarre", name: "Jarre", color: "#3f8fd2",
  tracks: [
    { key: "kick", label: "Kick", code: 's("bd ~ ~ bd ~ ~ bd ~").bank("{B}").lpf(2500).gain(.85)' },
    { key: "snare", label: "Snare", code: 's("~ ~ sd ~").bank("{B}").gain(.55).room(.3)' },
    { key: "hats", label: "Hi-Hats", code: 's("hh*8").bank("{B}").gain("[.35 .2]*4").hpf(5000)' },
    { key: "open", label: "Offene Hat", code: 's("[~ oh]*2").bank("{B}").gain(.25).hpf(4000).pan(sine.slow(4))' },
    { key: "seq", label: "Sequencer", code: 'n("0 0 7 0 5 0 3 0 0 0 7 0 <5 8> 0 <3 2> 0").scale("{K}2:{S}").s("sawtooth").lpf(sine.range(400,1800).slow(16)).lpenv(2).lpd(.08).lpq(8).decay(.1).sustain(0).gain(.35)' },
    { key: "bass", label: "Bass", code: 'n("<0 -2 -3 -4>").struct("x ~ ~ x ~ ~ x ~").scale("{K}1:{S}").s("square").lpf(500).decay(.25).sustain(.2).gain(.45)' },
    { key: "strings", label: "String-Machine", code: 'n("<[0,2,4] [-2,0,2] [-3,-1,1] [-4,-2,0]>").scale("{K}3:{S}").s("supersaw").unison(6).detune(.35).spread(.8).attack(.8).release(2).lpf(2200).phaser(.3).phaserdepth(.7).gain(.15).room(.6).roomsize(5)' },
    { key: "lead", label: "Singender Lead", code: 'n("<[4 ~ ~ ~ 2 ~ 4 5] [4 ~ ~ ~ ~ ~ ~ ~] [2 ~ ~ ~ 0 ~ 2 4] [2 ~ ~ ~ ~ ~ ~ ~]>").scale("{K}4:{S}").s("sawtooth").lpf(2000).attack(.05).release(.6).vib(5).vibmod(.15).gain(.2).delay(.4).delaytime(.375).delayfeedback(.45).room(.5)' },
    { key: "arp", label: "Arpeggio", code: 'n("0 2 4 7 4 2 0 2").scale("{K}4:{S}").s("triangle").decay(.12).sustain(0).gain(.18).delay(.35).pan(sine.slow(6))' },
    { key: "laser", label: "Laserharfe", code: 'n("<[0 ~ 4 ~ 7 ~ ~ ~] [~ ~ ~ ~ 9 ~ 7 ~]>").scale("{K}4:{S}").s("square").lpf(1600).lpenv(3).lpd(.2).decay(.4).sustain(0).gain(.16).room(.8).roomsize(7).delay(.5)' },
    { key: "vox", label: "Stimmen", code: 's("speech:<0 3 5 2>").struct("~ ~ x ~ ~ ~ ~ ~ ~ x ~ ~ ~ ~ ~ ~").speed("<1 1.2 .8>").hpf(300).vowel("<a o>").delay(.4).room(.5).gain(.45)' },
    { key: "wind", label: "Wind und Meer", code: 's("pink").lpf(sine.range(300,2400).slow(8)).hpf(150).gain(sine.range(.03,.09).slow(8)).pan(sine.slow(11)).room(.6)' },
  ],
  variants: [
    { key: "oxy4", name: "Oxygène IV", bpm: 115, bank: "KorgMinipops", scale: "minor", key0: "C",
      desc: "Minipops-Rhythmus, hüpfender Bass, singender Lead, Wind", on: ["kick", "snare", "hats", "bass", "strings", "lead", "wind"],
      tracks: {
        bass: 'n("<[0 ~ 7 ~ 0 ~ 7 ~] [-2 ~ 5 ~ -2 ~ 5 ~] [-3 ~ 4 ~ -3 ~ 4 ~] [-4 ~ 3 ~ -4 ~ 3 ~]>").scale("{K}2:{S}").s("square").lpf(900).decay(.15).sustain(.1).gain(.4)',
      } },
    { key: "oxy2", name: "Oxygène II", bpm: 100, bank: "KorgMinipops", scale: "dorian", key0: "D",
      desc: "Schwebend, langsam, Flächen und Meeresrauschen", on: ["hats", "open", "strings", "lead", "arp", "wind"],
      tracks: {
        lead: 'n("<[0 ~ ~ ~ ~ ~ 2 ~] [4 ~ ~ ~ 3 ~ 2 ~] [1 ~ ~ ~ ~ ~ ~ ~] [~ ~ ~ ~ ~ ~ ~ ~]>").scale("{K}4:{S}").s("sine").fm(1).fmh(2).attack(.2).release(1.2).vib(4).vibmod(.25).gain(.22).delay(.5).delaytime(.5).delayfeedback(.55).room(.7)',
      } },
    { key: "equi5", name: "Équinoxe V", bpm: 120, bank: "KorgMinipops", scale: "minor", key0: "A",
      desc: "Rasender Sequencer, Strings, treibend", on: ["kick", "snare", "hats", "open", "seq", "strings", "lead"], tracks: {} },
    { key: "magnetic", name: "Magnetic Fields II", bpm: 122, bank: "RolandCompurhythm78", scale: "major", key0: "E",
      desc: "Fröhlicher Dur-Hook, Sequencer, helle Hats", on: ["kick", "snare", "hats", "open", "seq", "bass", "arp", "lead"],
      tracks: {
        lead: 'n("<[7 ~ 9 ~ 7 ~ 4 ~] [5 ~ 4 ~ 2 ~ ~ ~] [7 ~ 9 ~ 11 ~ 9 ~] [7 ~ ~ ~ ~ ~ ~ ~]>").scale("{K}4:{S}").s("square").lpf(2600).attack(.01).decay(.2).sustain(.4).release(.3).vib(6).vibmod(.1).gain(.18).delay(.3).delaytime(.1875)',
      } },
    { key: "zoolook", name: "Zoolook", bpm: 108, bank: "LinnDrum", scale: "phrygian", key0: "E",
      desc: "Stimmen-Collage, funkiger Bass, Linn-Drums", on: ["kick", "snare", "hats", "bass", "strings", "vox", "laser"],
      tracks: {
        kick: 's("bd ~ ~ bd ~ bd ~ ~").bank("{B}").gain(.9)',
        bass: 'n("0 ~ 0 [~ 0] ~ 1 ~ <-1 3>").scale("{K}1:{S}").s("sawtooth").lpf(700).lpenv(2).lpd(.1).decay(.15).sustain(0).gain(.6)',
      } },
    { key: "rendezvous", name: "Rendez-Vous IV", bpm: 118, bank: "LinnDrum", scale: "major", key0: "G",
      desc: "Hymne mit Laserharfe, großer Hall, gerade Kick", on: ["kick", "snare", "hats", "bass", "strings", "laser", "lead"],
      tracks: { kick: 's("bd*4").bank("{B}").lpf(3000).gain(.9)' } },
    { key: "chrono", name: "Chronologie", bpm: 124, bank: "RolandCompurhythm78", scale: "minor", key0: "F",
      desc: "Tickender Uhr-Rhythmus, Arpeggio, dunkle Strings", on: ["kick", "hats", "open", "seq", "arp", "strings", "wind"],
      tracks: {
        hats: 's("hh*16").bank("{B}").gain("[.3 .1 .18 .1]*4").hpf(6000)',
        arp: 'n("0 2 4 6 4 2 0 2").scale("{K}4:{S}").s("triangle").decay(.1).sustain(0).gain(.16).delay(.4).delaytime(.1875).pan(sine.slow(3))',
      } },
  ],
};
