/*
  Neumorph's background set (docs/frontend-os.md#neumorph): the ids the Background picker offers
  under this OS, first entry = default. Each id is painted by a body[data-background="<id>"] rule
  in chrome.css: very low-contrast relief built from layered gradients on the one surface colour,
  so windows and keys still read as moulded from the same material. Data only (os/registry.js).
*/

export default Object.freeze([
  Object.freeze({ id: "porcelain", label: "Porcelain" }),
  Object.freeze({ id: "dunes", label: "Dunes" }),
  Object.freeze({ id: "pillows", label: "Pillows" }),
  Object.freeze({ id: "rings", label: "Rings" }),
  Object.freeze({ id: "orb", label: "Orb" }),
]);
