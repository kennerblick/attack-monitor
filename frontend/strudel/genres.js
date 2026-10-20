// Genre-Presets: je Spur ein Strudel-Pattern. Platzhalter: {K} Grundton (z. B. "A"),
// {S} Skala des Genres, {B} Drum-Machine-Bank. "{K}1:{S}" wird also zu "A1:minor".
export const LAYERS = [
  { key: "kick", label: "Kick", hint: "Q" },
  { key: "snare", label: "Snare / Clap", hint: "W" },
  { key: "hats", label: "Hi-Hats", hint: "E" },
  { key: "perc", label: "Percussion", hint: "R" },
  { key: "bass", label: "Bass", hint: "A" },
  { key: "chords", label: "Akkorde", hint: "S" },
  { key: "lead", label: "Lead", hint: "D" },
  { key: "atmo", label: "Atmosphäre", hint: "F" },
];

export const GENRES = [
  {
    key: "techno", name: "Techno", bpm: 132, bank: "RolandTR909", scale: "minor", key0: "A",
    color: "#3987e5", on: ["kick", "hats", "bass", "perc"],
    layers: {
      kick: 's("bd*4").bank("{B}").gain(1.1)',
      snare: 's("~ cp ~ cp").bank("{B}").gain(.6).room(.2)',
      hats: 's("[~ hh]*4, ~ ~ ~ oh").bank("{B}").gain(.5)',
      perc: 's("~ rim ~ ~ rim ~ rim ~").bank("{B}").gain(.4)',
      bass: 'n("[~ 0]*4").scale("{K}1:{S}").s("sawtooth").lpf(450).lpq(6).decay(.14).sustain(0).gain(.75)',
      chords: 'n("<[0,2,4] [-1,1,3] [-2,0,2] [-3,-1,1]>").scale("{K}3:{S}").struct("~ x ~ ~ ~ ~ x ~").s("supersaw").decay(.25).sustain(0).lpf(2200).gain(.32)',
      lead: 'n("0 2 4 7 4 2 0 [-3 -1]").scale("{K}4:{S}").s("square").lpf(sine.range(800,3000).slow(8)).decay(.12).sustain(0).gain(.22).delay(.3)',
      atmo: 'n("<[0,4,7] [-2,2,5]>").scale("{K}2:{S}").s("sawtooth").attack(1.5).release(2).lpf(700).gain(.2).slow(2)',
    },
  },
  {
    key: "house", name: "House", bpm: 124, bank: "RolandTR909", scale: "dorian", key0: "F",
    color: "#d95926", on: ["kick", "snare", "hats", "chords"],
    layers: {
      kick: 's("bd*4").bank("{B}")',
      snare: 's("~ cp ~ cp").bank("{B}").gain(.7)',
      hats: 's("[~ oh]*4, hh*16").bank("{B}").gain("[.45 .25]*8")',
      perc: 's("~ ~ ~ rim ~ ~ rim ~").bank("{B}").gain(.4)',
      bass: 'n("0 ~ 0 [~ 0] ~ 0 ~ 4").scale("{K}1:{S}").s("triangle").lpf(800).decay(.2).sustain(.2).gain(.9)',
      chords: 'n("<[0,2,4,6] [-2,0,2,4] [-3,-1,1,3] [-1,1,3,5]>").scale("{K}3:{S}").struct("~ x ~ x ~ ~ x ~").s("piano").gain(.55).room(.3)',
      lead: 'n("<4 6 7 9>(3,8,2)").scale("{K}4:{S}").s("triangle").decay(.2).sustain(0).gain(.3).delay(.35)',
      atmo: 'n("<[0,2,4] [-3,-1,1]>").scale("{K}2:{S}").s("supersaw").attack(1).release(1.5).lpf(1200).gain(.15).slow(2)',
    },
  },
  {
    key: "dnb", name: "Drum & Bass", bpm: 172, bank: "AkaiMPC60", scale: "minor", key0: "E",
    color: "#199e70", on: ["kick", "snare", "hats", "bass"],
    layers: {
      kick: 's("bd ~ ~ ~ ~ ~ bd ~ ~ ~ bd ~ ~ ~ ~ ~").bank("{B}").gain(1.1)',
      snare: 's("~ ~ ~ ~ sd ~ ~ ~ ~ ~ ~ ~ sd ~ ~ ~").bank("{B}").gain(.9)',
      hats: 's("hh*8").bank("{B}").gain("[.5 .3]*4")',
      perc: 's("~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ [~ rim] ~").bank("{B}").gain(.5)',
      bass: 'n("<0 0 3 -2>").scale("{K}1:{S}").s("sawtooth").lpf(sine.range(200,900).fast(2)).lpq(8).sustain(.8).gain(.7)',
      chords: 'n("<[0,2,4] [3,5,7] [-2,0,2] [1,3,5]>").scale("{K}3:{S}").s("supersaw").attack(.3).release(.8).lpf(1600).gain(.22).slow(2)',
      lead: 'n("~ 7 ~ 4 ~ ~ 2 ~").scale("{K}4:{S}").s("sine").decay(.3).sustain(0).gain(.35).delay(.45)',
      atmo: 'n("<[0,4] [-2,2]>").scale("{K}2:{S}").s("sawtooth").attack(1).release(2).lpf(500).gain(.18).slow(2)',
    },
  },
  {
    key: "lofi", name: "Lo-Fi", bpm: 82, bank: "LinnDrum", scale: "major", key0: "D",
    color: "#c98500", on: ["kick", "snare", "hats", "chords", "bass"],
    layers: {
      kick: 's("bd ~ ~ bd ~ ~ bd ~").bank("{B}").lpf(1200)',
      snare: 's("~ sd").bank("{B}").gain(.6).lpf(3000)',
      hats: 's("hh*8").bank("{B}").gain("[.35 .2]*4").lpf(4000)',
      perc: 's("~ ~ sh ~ ~ sh ~ sh").bank("{B}").gain(.3)',
      bass: 'n("<0 -3 -2 -4>").scale("{K}1:{S}").s("sine").sustain(.5).gain(.9)',
      chords: 'n("<[0,2,4,6] [-3,-1,1,3] [-2,0,2,4] [-4,-2,0,2]>").scale("{K}3:{S}").s("piano").gain(.6).lpf(2400).room(.4)',
      lead: 'n("~ 4 ~ [6 4] ~ 2 ~ ~").scale("{K}4:{S}").s("piano").gain(.35).lpf(2000).delay(.3)',
      atmo: 'n("<[0,4] [-1,3]>").scale("{K}3:{S}").s("triangle").attack(.6).release(2).gain(.35).slow(2)',
    },
  },
  {
    key: "synthwave", name: "Synthwave", bpm: 100, bank: "LinnDrum", scale: "minor", key0: "C",
    color: "#d55181", on: ["kick", "snare", "hats", "bass", "lead"],
    layers: {
      kick: 's("bd ~ bd ~").bank("{B}")',
      snare: 's("~ sd ~ sd").bank("{B}").gain(.8).room(.5)',
      hats: 's("hh*8").bank("{B}").gain(.35)',
      perc: 's("~ ~ ~ ~ ~ ~ ~ tb").bank("{B}").gain(.4)',
      bass: 'n("<0 -2 -4 -3>").struct("x*8").scale("{K}1:{S}").s("sawtooth").lpf(700).decay(.12).sustain(.2).gain(.6)',
      chords: 'n("<[0,2,4] [-2,0,2] [-4,-2,0] [-3,-1,1]>").scale("{K}3:{S}").s("supersaw").attack(.05).release(.6).lpf(2600).gain(.3)',
      lead: 'n("<[7 ~ 6 4] [2 ~ 4 ~] [0 ~ 2 4] [6 4 2 ~]>").scale("{K}4:{S}").s("sawtooth").lpf(2800).attack(.01).decay(.25).sustain(.3).gain(.25).delay(.4)',
      atmo: 'n("<[0,4,7] [-2,2,5]>").scale("{K}2:{S}").s("supersaw").attack(2).release(2).lpf(900).gain(.15).slow(2)',
    },
  },
  {
    key: "ambient", name: "Ambient", bpm: 70, bank: "RolandTR808", scale: "lydian", key0: "G",
    color: "#9085e9", on: ["chords", "atmo", "lead"],
    layers: {
      kick: 's("bd ~ ~ ~ ~ ~ ~ ~").bank("{B}").gain(.7).lpf(500)',
      snare: 's("~ ~ rim ~").bank("{B}").gain(.3).room(.8)',
      hats: 's("~ sh ~ sh").bank("{B}").gain(.3)',
      perc: 's("~ ~ ~ cb").bank("{B}").gain(.35).speed(.5)',
      bass: 'n("<0 -3>").scale("{K}2:{S}").s("triangle").attack(.3).release(2).lpf(600).gain(.6)',
      chords: 'n("<[0,2,4,6] [1,3,5,7]>").scale("{K}3:{S}").s("supersaw").attack(2).release(3).lpf(1400).gain(.25).slow(2)',
      lead: 'n("0 [2 4] ~ 7 ~ 9 ~ ~").scale("{K}4:{S}").s("triangle").decay(.6).sustain(0).gain(.3).delay(.6).room(.6)',
      atmo: 'n("<[0,4] [2,6]>").scale("{K}2:{S}").s("sawtooth").attack(3).release(3).lpf(600).gain(.18).slow(4)',
    },
  },
];

export const KEYS = ["C", "D", "E", "F", "G", "A", "B"];
